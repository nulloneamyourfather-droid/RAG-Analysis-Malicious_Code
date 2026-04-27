# RAG 实验结果汇总

## rag_vs_no_rag
- 样本：`1.bin`
- 设置：`top_k=3, function_limit=5, backend=semantic`

| label | function_count | suspicious_count | runtime_like_count | candidate_attack_total | attack_doc_hit_count | api_chain_hit_count | similar_func_hit_count | avg_candidate_attack_count | avg_evidence_lines |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| with_rag | 5 | 5 | 0 | 30 | 5 | 5 | 5 | 6.0 | 4.6 |
| without_rag | 5 | 0 | 0 | 0 | 0 | 0 | 0 | 0.0 | 0.0 |

## source_combinations
- 样本：`1.bin`
- 设置：`top_k=3, function_limit=5, backend=semantic`

| label | function_count | suspicious_count | runtime_like_count | candidate_attack_total | attack_doc_hit_count | api_chain_hit_count | similar_func_hit_count | avg_candidate_attack_count | avg_evidence_lines | enabled_sources |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| attack_only | 5 | 5 | 0 | 15 | 5 | 0 | 0 | 3.0 | 2.6 | ['ATTACK'] |
| api_chain_only | 5 | 1 | 0 | 15 | 0 | 5 | 0 | 3.0 | 2.6 | ['API_CHAIN'] |
| ida_semantic_only | 5 | 0 | 0 | 0 | 0 | 0 | 5 | 0.0 | 2.6 | ['IDA_SEMANTIC'] |
| attack_api_chain | 5 | 5 | 0 | 30 | 5 | 5 | 0 | 6.0 | 3.6 | ['ATTACK', 'API_CHAIN'] |
| all_sources | 5 | 5 | 0 | 30 | 5 | 5 | 5 | 6.0 | 4.6 | ['ATTACK', 'API_CHAIN', 'IDA_SEMANTIC'] |

## chunking_strategies
- 样本：`1.bin`
- 设置：`function_limit=5`

| strategy | function_count | avg_top_score | nonzero_hit_count | attack_top_hit_count |
| --- | --- | --- | --- | --- |
| summary_only | 5 | 0.811863 | 5 | 0 |
| keyword_focused | 5 | 0.737459 | 5 | 0 |
| full_content | 5 | 0.927989 | 5 | 0 |
