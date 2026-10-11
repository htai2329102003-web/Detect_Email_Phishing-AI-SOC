"""Compatibility entry point: python -m scripts.run_eval --manifest PATH."""

from eval.run_eval import main

if __name__ == "__main__":
    raise SystemExit(main())
