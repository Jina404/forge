package core

import "errors"

// Stage represents a campaign stage.
type Stage string

const (
	StageRecon          Stage = "Recon"
	StageAuthTesting    Stage = "Authentication Testing"
	StageAuthZTesting   Stage = "Authorization Testing"
	StageInjection      Stage = "Injection Testing"
	StageValidation     Stage = "Validation"
	StageReporting      Stage = "Reporting"
)

// Workflow defines an ordered set of stages.
type Workflow struct {
	Stages []Stage
}

// DefaultWorkflow returns the standard autonomous assessment flow.
func DefaultWorkflow() Workflow {
	return Workflow{
		Stages: []Stage{
			StageRecon,
			StageAuthTesting,
			StageAuthZTesting,
			StageInjection,
			StageValidation,
			StageReporting,
		},
	}
}

// Validate confirms workflow contains at least one stage.
func (w Workflow) Validate() error {
	if len(w.Stages) == 0 {
		return errors.New("workflow must include at least one stage")
	}
	return nil
}
