# SENTINEL — Product Direction & Command Center Brief
**Approved direction:** Hybrid original identity · Command Center priority · High redesign freedom.
## Product thesis
SENTINEL is an evidence-led on-chain investigation environment. It helps an analyst move from a target (address, transaction, contract) to source-backed observations, relationship analysis, candidate fund-flow paths, review signals, and a reproducible case.
It is not a wallet tracker with an AI label, a generic analytics dashboard, or a claim of complete Arkham-equivalent chain coverage.
## Experience hierarchy
### 1. Command Center (primary landing experience)
Must answer current chain/provider/source scope; current or most recent investigation, if one exists; evidence status (verified, conflicting, unknown, partial, truncated); coverage window and blind spots; and a clear action to start or resume an investigation.
No fabricated activity feed, global threat count, risk score, or live badge. With no session data, show a purposeful first-investigation state.
### 2. Investigation workspace
A coherent workspace preserves the selected target while moving among target profile and contract/account inspection; activity and evidence timeline; relationship/topology graph; token and native value-flow observations; bounded candidate fund tracing; topology and burst signals; entity comparison and evidence gap analysis.
### 3. Case workspace
A case preserves source files, observations, hypotheses, review decisions, provenance, validation, and exportable report artifacts. Observed facts remain separate from analyst interpretation.
## Visual identity
Hybrid, original, restrained: intelligence-terminal information density with premium editorial hierarchy; dark graphite/deep blue-black surfaces; muted steel text; controlled cyan for neutral interaction; amber for caution/unverified; red only for conflicts/errors; green only for verified/success. Use precise typography, consistent spacing, strong grid, crisp dividers, restrained depth. Graph visualizations must explain relationships and evidence. Mobile retains the primary investigative action and readable evidence.
Avoid generic dashboard card grids, fake maps, decorative 3D, arbitrary neon, emoji-as-icons, placeholder KPIs, and copied Arkham layouts.
## Data and trust contract
Every observation should retain chain ID/network, provider/indexer, queried block range/source scope, transaction hash/log index/block number where applicable, raw amount/token contract for token events, truncation/pagination/missing-data indicators, and source-specific limitations.
A candidate path is a heuristic, not proof the same units moved. Topology is not ownership. Burst detection is not proof of automation. A shared address is not proof of common control. No automatic maliciousness verdict.
## First implementation milestone
**Command Center → Investigation handoff.**
1. Audit the existing overview and mounted modules before visual redesign.
2. Replace static or potentially misleading status claims with state derived from selected network/source/investigation state, or label them as supported capabilities.
3. Make the first-investigation action the visual focal point.
4. Preserve target context when navigating to graph and case analysis.
5. Establish shared visual tokens and responsive layout rules before expanding feature count.
6. Add end-to-end checks for the investigator's primary path.
## Acceptance criteria
No fake activity or fabricated metrics. Every navigation item lands on a real destination. One target can be inspected and its evidence followed into graph and case analysis without losing context. Source scope, partial coverage, and uncertainty remain visible. Desktop and mobile both support the primary path. Relevant tests pass; visual validation is separately reported.