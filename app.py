if __name__ == "__main__":
    ensure_runtime_dirs()
    rotate_generation_log()
    log_startup_warnings()
    init_db()
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8080")),
        debug=False,
    )