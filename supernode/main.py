"""SuperNode 启动入口。

开发运行：
    python -m supernode.main
    或
    uvicorn supernode.api:app --host 127.0.0.1 --port 8000
"""

import logging
import sys


def main():
    import uvicorn

    from .api import create_app
    from .config import get_settings

    settings = get_settings()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    app = create_app(settings)

    print(f"SuperNode v0.1 启动: http://{settings.host}:{settings.port}")
    print(f"API 文档: http://{settings.host}:{settings.port}/docs")
    print(f"邮件后端: {settings.email_backend}")
    print(f"数据库: {settings.database_url}\n")

    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
