import { buildPptx, createDeck } from "/data/skills/pptx/scripts/pptx_builder_runtime.mjs"
import { applyRecipeDeckPlan } from "/data/skills/pptx/scripts/slide_recipes.mjs"

const deck = createDeck({ width: 1280, height: 720 })
const slidePlan = [
  {
    recipeId: "cover-editorial",
    content: {
      eyebrow: "Topic 2 · GitHub CI/CD security",
      title: "ActionGuard AutoAudit",
      subtitle: "From vulnerability detection to evidence, risk scoring, patch previews, reports, and maintainer notification.",
      section: "Hackathon build · 2026",
    },
  },
  {
    recipeId: "big-claim",
    content: {
      claim: "A scanner finds problems. ActionGuard closes the audit loop.",
      support: "Normalize security evidence, score risk, and produce reviewable remediation.",
    },
  },
  {
    recipeId: "two-column",
    content: {
      eyebrow: "System architecture",
      title: "One resilient audit pipeline",
      left: "DETECT\n\nTrigger with contents: read. Run zizmor plus focused custom auditors. Isolate missing-tool and scanner failures.",
      right: "DELIVER\n\nNormalize findings. Calculate scores. Build controlled remediation. Publish HTML, JSON, artifact, and optional email.",
    },
  },
  {
    recipeId: "evidence-panel",
    content: {
      eyebrow: "Differentiator",
      title: "Agentic CI risks need dedicated controls",
      claim: "Privilege turns prompt injection into code execution.",
      evidence: [
        ["AG-AI-001", "Issue, PR, or comment text reaches an agent"],
        ["AG-AI-002", "Model output is executed as shell commands"],
        ["AG-AI-003", "Comment-triggered action lacks trust validation"],
        ["AG-AI-004/005", "Write permission or secrets amplify impact"],
      ],
    },
  },
  {
    recipeId: "table-led",
    content: {
      eyebrow: "MVP coverage",
      title: "Thirteen modules, one normalized result",
      table: {
        headers: ["Audit surface", "Detector", "Output"],
        rows: [
          ["GitHub Actions", "zizmor JSON v1", "Rule, file, line, severity"],
          ["Secrets & env", "9 patterns + file policy", "Redacted evidence"],
          ["Artifacts", "Workflow-aware YAML rules", "Safe upload patch"],
          ["Code & dependencies", "Ruff, Bandit, npm, pip-audit", "Non-blocking status"],
          ["Repository hygiene", "Required-file checks", "Templates and priorities"],
        ],
      },
      takeaway: "Tool failures are isolated and recorded.",
    },
  },
  {
    recipeId: "comparison",
    content: {
      eyebrow: "Remediation control",
      title: "Patch help without unsafe automation",
      leftTitle: "Safe to suggest",
      leftBody: "Add ignore patterns, reduce artifact retention, narrow upload paths, add timeouts, and create missing governance files.",
      rightTitle: "Manual review required",
      rightBody: "Delete committed secrets, rotate credentials, change production triggers, alter write permissions, or execute deployment changes.",
    },
  },
  {
    recipeId: "metric-grid",
    content: {
      eyebrow: "Demo result",
      title: "The vulnerable fixture produces decisive evidence",
      metrics: [
        { value: "0", label: "Overall score / 100" },
        { value: "7", label: "Critical findings" },
        { value: "3", label: "High findings" },
        { value: "5/5", label: "Agentic rules triggered" },
        { value: "0", label: "Full secrets printed" },
        { value: "18", label: "Normalized findings" },
      ],
    },
  },
  {
    recipeId: "timeline-clean",
    content: {
      eyebrow: "Strict build order",
      title: "Execution followed the required sequence",
      events: [
        { label: "Detection", body: "Core rules and integrations" },
        { label: "Normalization", body: "Finding schema" },
        { label: "Reporting", body: "HTML and JSON" },
        { label: "Remediation", body: "Controlled patch previews" },
        { label: "Delivery", body: "Email, artifact, and polish" },
      ],
    },
  },
  {
    recipeId: "closing-takeaways",
    content: {
      eyebrow: "Submission position",
      title: "Why ActionGuard stands out",
      takeaways: [
        "Extends zizmor instead of rebuilding proven CI/CD rules.",
        "Adds practical defenses for AI-agent workflow injection.",
        "Turns findings into safe, reviewable remediation evidence.",
        "Runs locally and in GitHub Actions without paid APIs or cloud hosting.",
      ],
    },
  },
]

applyRecipeDeckPlan(deck, slidePlan)
await buildPptx(deck, {
  scenePath: "/data/actionguard-autoaudit/slides/build/actionguard.scene.json",
  outputPath: "/data/actionguard-autoaudit/slides/ActionGuard-AutoAudit.pptx",
  reportPath: "/data/actionguard-autoaudit/slides/build/actionguard.build-report.json",
  previewDir: "/data/actionguard-autoaudit/slides/build/preview",
  layoutDir: "/data/actionguard-autoaudit/slides/build/layout",
})
