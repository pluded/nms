# This is the __init__.py file for the nms package.
import logging
from .utils.logger import setup_logging

# Configure logging for the entire nms package when it's imported.
# This makes sure that any logger obtained via logging.getLogger('nms.module_name')
# or logging.getLogger(__name__) within the nms package will have this configuration.
setup_logging()

# You can also get a specific logger for this __init__ file if needed
# logger = logging.getLogger(__name__)
# logger.info("NMS package initialized and logging configured.")
