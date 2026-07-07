This is the code for the paper `Aggregator-Based Voting using proof of Partition`, by Marius Lombard-Platet and Doron Zarchy, accepted at AsiaCCS 2026. The code is here for demonstration purposes only, and has not been audited for security issues.

## Benchmark for the EPA protocol

Our own results are available in `log.txt`. Run `python parse_logs.py` to get the LaTeX code for the tables and graphs used in the paper.

If you want to run the benchmark on your machine, you will need to install Rust. Then, `cargo run --release > log.txt` (will overwrite the `log.txt` file). The benchmark will run for around 50 hours on an Intel i5-10310U CPU.
