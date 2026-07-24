# System Design

```text
                 User

                  |
                  v

              Forge API

                  |
                  v

          Campaign Controller

                  |
        ---------------------
        |                   |

    AI Agent          Attack Engine

        |                   |

    Planner          Vulnerability Tests

        |                   |

        ---------------------

                  |

          Evidence System

                  |

             Reporting
```

## Components

- Forge API: authentication, authorization, campaign endpoints, tenant boundaries
- Campaign controller: lifecycle state transitions and workflow execution
- AI agent: plan generation, reasoning, adaptive strategy guidance
- Attack engine: concurrent load, fuzzing, detector execution
- Evidence system: request/response/payload/timestamp/screenshot capture
- Reporting: executive and technical output generation
