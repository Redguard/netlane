from importlib import metadata

APP_NAME = metadata.metadata(__name__)["Name"]
