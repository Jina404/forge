package agent

import (
	"context"
	"fmt"
)

// PlanStage is one stage of an autonomous attack plan.
type PlanStage struct {
	Name        string
	Description string
}

// AttackPlan is an ordered execution plan.
type AttackPlan struct {
	TargetURL string
	Stages    []PlanStage
}

// Planner produces ordered plans from objectives and discoveries.
type Planner struct{}

func NewPlanner() *Planner { return &Planner{} }

func (p *Planner) Plan(_ context.Context, objective Objective, discoveries []string) (AttackPlan, error) {
	if objective.TargetURL == "" {
		return AttackPlan{}, fmt.Errorf("target URL is required")
	}

	stages := []PlanStage{
		{Name: "technology_discovery", Description: "Identify frameworks, server stack, and exposed interfaces."},
		{Name: "endpoint_discovery", Description: "Map routes, parameters, and high-risk entry points."},
		{Name: "authentication_analysis", Description: "Inspect auth mechanisms, token handling, and session controls."},
		{Name: "authorization_testing", Description: "Attempt privilege escalation and broken access control scenarios."},
		{Name: "injection_testing", Description: "Probe injection surfaces with controlled payloads."},
		{Name: "validation", Description: "Confirm reproducibility and confidence of findings."},
	}

	if len(discoveries) > 0 {
		stages = append(stages, PlanStage{Name: "targeted_follow_up", Description: "Prioritize tests based on discovered attack surface."})
	}

	return AttackPlan{TargetURL: objective.TargetURL, Stages: stages}, nil
}
