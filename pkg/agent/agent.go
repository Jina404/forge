package agent

import "context"

// Objective tracks what the autonomous agent is trying to achieve.
type Objective struct {
	CampaignID string
	TargetURL  string
	Goal       string
}

// Action captures a single decision and resulting observation.
type Action struct {
	Name       string
	Reason     string
	Outcome    string
	Confidence float64
}

// State maintains short-term execution memory.
type State struct {
	Objective   Objective
	Actions     []Action
	Discoveries []string
	Confidence  float64
}

// Coordinator orchestrates planning, reasoning, and decisions.
type Coordinator struct {
	planner   *Planner
	reasoner  *Reasoner
	memory    *Memory
	decision  *DecisionEngine
}

func NewCoordinator(planner *Planner, reasoner *Reasoner, memory *Memory, decision *DecisionEngine) *Coordinator {
	return &Coordinator{planner: planner, reasoner: reasoner, memory: memory, decision: decision}
}

func (c *Coordinator) Step(ctx context.Context, state State) (State, error) {
	plan, err := c.planner.Plan(ctx, state.Objective, state.Discoveries)
	if err != nil {
		return state, err
	}
	analysis, err := c.reasoner.Reason(ctx, state, plan)
	if err != nil {
		return state, err
	}
	action := c.decision.SelectAction(plan, analysis)
	state.Actions = append(state.Actions, action)
	state.Confidence = action.Confidence
	_ = c.memory.Append(state.Objective.CampaignID, action)
	return state, nil
}
