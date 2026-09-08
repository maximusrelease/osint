# Engineering & Security Squad Manifest

This workspace (`c:\Dev`) is equipped with four specialized AI agents configured for cross-functional collaboration, architectural excellence, and rigorous security engineering.

---

## 1. Squad Roster

| Agent Name | Role | Primary Focus & Domain |
| :--- | :--- | :--- |
| **`neo`** | **Cyber Security Architect & Researcher** | Red team & pentest workflow analysis, Detection-as-Code (Sigma/YARA/KQL), SOC engineering, AI/LLM security (OWASP Top 10 for LLMs, prompt injection defense, guardrails), threat modeling (STRIDE/PASTA), and Zero Trust architecture. |
| **`full`** | **Full Stack Engineer & Architect** | End-to-end web & application systems, API contract design, full-stack frameworks (Next.js, Remix, Node, Python, Go), database modeling & ORM migrations, client-server state sync, and CI/CD pipelines. |
| **`front`** | **Frontend Architect & Developer** | Modern UI/UX design systems, modern CSS (container queries, micro-interactions, dark mode), Core Web Vitals (LCP, INP, CLS), accessibility (WCAG 2.1/2.2 AA/AAA), and reactive client state. |
| **`back`** | **Backend Architect & Engineer** | Distributed systems, high concurrency, relational & NoSQL databases, transactional integrity (ACID, Saga), message streaming (Kafka, RabbitMQ), API gateways, and three pillars of observability (metrics, logs, traces). |

---

## 2. Agent Configuration Locations

Each agent is defined in two standard Antigravity locations for complete compatibility:
- **Directory format**: `.agents/agents/<name>/agent.md`
- **File format**: `.agents/agents/<name>.md`

```text
.agents/
└── agents/
    ├── neo/
    │   └── agent.md
    ├── neo.md
    ├── full/
    │   └── agent.md
    ├── full.md
    ├── front/
    │   └── agent.md
    ├── front.md
    ├── back/
    │   └── agent.md
    └── back.md
```

---

## 3. How to Use & Switch Agents

1. **Select as Primary Agent**:
   - In the Antigravity TUI or CLI, run `/agents` to view and switch between `neo`, `full`, `front`, and `back`.
   - In Antigravity IDE / 2.0 desktop app, open the Agent Selector dropdown in the chat canvas.

2. **Delegate as Subagents**:
   - The primary agent can delegate sub-tasks to these specialized agents concurrently without cluttering the primary conversation context.

3. **Multi-Agent Collaboration Workflows**:
   - **New Feature Delivery**:
     - `front` crafts the UI design system, accessible components, and client interactions.
     - `back` architectures the high-throughput service, database models, and streaming endpoints.
     - `full` wires contracts, schemas (Zod/OpenAPI), state management, and deployment.
     - `neo` audits the PR for vulnerabilities, ensures authN/authZ enforcement, threat models the architecture, and writes Detection-as-Code rules for SOC alerting.
   - **AI/LLM Application**:
     - `neo` defines guardrails, prompt boundary defenses, tool execution sandboxes, and data isolation.
     - `full` implements the RAG pipeline, vector database integration, and agent orchestration.
