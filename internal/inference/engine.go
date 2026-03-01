// Package inference wraps ONNX Runtime for running the trained
// XGBoost/RF model on feature vectors extracted from eBPF maps.
package inference

import (
	"fmt"
	"sync"

	ort "github.com/yalue/onnxruntime_go"

	"github.com/aliciamew/ddos-early-warning/internal/features"
)

// Engine manages the ONNX Runtime session and performs inference.
type Engine struct {
	mu         sync.Mutex
	session    *ort.AdvancedSession
	inputName  string
	outputName string
}

// Result holds the inference output for a single source IP.
type Result struct {
	SrcIP    uint32
	Score    float32 // probability of being an attack (0..1)
	IsAttack bool    // Score > threshold
	Features [features.VectorSize]float32
}

// NewEngine initialises ONNX Runtime and loads the model.
func NewEngine(modelPath string) (*Engine, error) {
	// Initialise the ONNX Runtime shared library.
	// The library path can be set via ORT_LIB_PATH env var.
	ort.SetSharedLibraryPath("libonnxruntime.so")
	if err := ort.InitializeEnvironment(); err != nil {
		return nil, fmt.Errorf("onnx init: %w", err)
	}

	// Define input/output shapes.
	// Input:  [1, 10] float32 — single sample, 10 features
	// Output: [1, 2]  float32 — probabilities [benign, attack]
	inputShape := ort.NewShape(1, int64(features.VectorSize))
	outputShape := ort.NewShape(1, 2)

	inputTensor, err := ort.NewEmptyTensor[float32](inputShape)
	if err != nil {
		return nil, fmt.Errorf("create input tensor: %w", err)
	}

	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return nil, fmt.Errorf("create output tensor: %w", err)
	}

	session, err := ort.NewAdvancedSession(
		modelPath,
		[]string{"features"},
		[]string{"probabilities"},
		[]ort.ArbitraryTensor{inputTensor},
		[]ort.ArbitraryTensor{outputTensor},
		nil, // default session options
	)
	if err != nil {
		return nil, fmt.Errorf("create session for %s: %w", modelPath, err)
	}

	return &Engine{
		session:    session,
		inputName:  "features",
		outputName: "probabilities",
	}, nil
}

// Predict runs inference on a batch of feature vectors.
// Returns a Result for each input vector.
func (e *Engine) Predict(vectors []features.Vector, threshold float32) ([]Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	results := make([]Result, 0, len(vectors))

	for _, vec := range vectors {
		score, err := e.predictSingle(vec.Features[:])
		if err != nil {
			return nil, fmt.Errorf("predict IP %d: %w", vec.SrcIP, err)
		}

		results = append(results, Result{
			SrcIP:    vec.SrcIP,
			Score:    score,
			IsAttack: score > threshold,
			Features: vec.Features,
		})
	}

	return results, nil
}

// predictSingle runs a single inference and returns the attack probability.
func (e *Engine) predictSingle(feats []float32) (float32, error) {
	// Create input tensor with the feature values
	inputShape := ort.NewShape(1, int64(features.VectorSize))
	inputTensor, err := ort.NewTensor(inputShape, feats)
	if err != nil {
		return 0, err
	}
	defer inputTensor.Destroy()

	// Create output tensor
	outputShape := ort.NewShape(1, 2)
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return 0, err
	}
	defer outputTensor.Destroy()

	// Run inference
	err = e.session.Run()
	if err != nil {
		return 0, err
	}

	// Output: [benign_prob, attack_prob]
	output := outputTensor.GetData()
	if len(output) < 2 {
		return 0, fmt.Errorf("unexpected output length: %d", len(output))
	}

	return output[1], nil // attack probability
}

// Close releases ONNX Runtime resources.
func (e *Engine) Close() {
	if e.session != nil {
		e.session.Destroy()
	}
	ort.DestroyEnvironment()
}
