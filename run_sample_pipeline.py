try:
    from .run_sample_pipeline_impl import main
except ImportError:
    from run_sample_pipeline_impl import main


if __name__ == "__main__":
    main()
