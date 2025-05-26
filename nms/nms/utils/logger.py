import logging
import sys

DEFAULT_LOG_FILE = "nms.log"
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(name)s - %(module)s.%(funcName)s:%(lineno)d - %(message)s"

# Keep track if basicConfig has been called
_logging_configured = False

def setup_logging(log_level=logging.INFO, log_file=DEFAULT_LOG_FILE, force_setup=False):
    """
    Configures a global logger for the nms application.

    This function should be called once, typically when the application starts.
    It sets up logging to both the console and a specified log file.

    Args:
        log_level: The minimum logging level (e.g., logging.INFO, logging.DEBUG).
        log_file: The path to the log file.
        force_setup: If True, forces reconfiguration even if already configured.
                     Useful for testing or specific scenarios.
    """
    global _logging_configured
    if _logging_configured and not force_setup:
        # logging.info("Logging already configured.") # Can't use logger here yet
        return

    # Get the root logger. Configuring the root logger will apply to all
    # loggers in the application unless they have their own specific config.
    # However, it's often better to get a specific logger for the application
    # to avoid interfering with other libraries' logging.
    # For this project, we'll configure a root-level logger for simplicity,
    # but allow modules to use specific loggers via logging.getLogger(__name__).
    
    # Using basicConfig is the simplest way to set up handlers and formatting.
    # It can only be called once effectively unless force=True is used (Python 3.8+).
    # For broader compatibility and control, manually adding handlers is better.

    # Remove any existing handlers from the root logger to avoid duplicate logs
    # if this function is called multiple times (e.g. in tests with force_setup)
    root_logger = logging.getLogger()
    if force_setup:
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close() # Close handler before removing

    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)

    # Create formatter and add it to the handlers
    formatter = logging.Formatter(LOG_FORMAT)
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add the handlers to the root logger
    # It's generally better to get a specific logger for the application,
    # e.g., logging.getLogger('nms'), and add handlers to it.
    # But for this project, configuring the root logger is acceptable.
    
    # We will configure the root logger
    logging.basicConfig(level=log_level,
                        format=LOG_FORMAT,
                        handlers=[console_handler, file_handler],
                        force=True if sys.version_info >= (3,8) else False # force is Py 3.8+
                        )
    
    # For older Python versions, if basicConfig was already called, 
    # the above might not work as expected without 'force'.
    # Manually adding handlers to the root logger is more robust across versions if force=True is not available.
    if sys.version_info < (3,8) and _logging_configured and force_setup :
        # If force=True was intended but not available, and we know we are re-configuring
        # we need to manually add handlers to the root logger
        # (basicConfig might not have added new handlers if it was already configured)
        # However, basicConfig with handlers list should replace existing handlers if any,
        # or add them if none. The primary issue is basicConfig not running again.
        # The logic here aims to ensure handlers are set up.
        # This path is complex due to basicConfig's nature. A simpler approach for full control
        # is to avoid basicConfig and always manually add/remove handlers on a specific app logger.
        
        # If we are here, it means basicConfig might not have re-added handlers on Python < 3.8
        # So, let's try to add them to the root logger directly if not already present.
        # This is a fallback and ideally `force=True` handles this.
        if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
             root_logger.addHandler(console_handler)
        if not any(isinstance(h, logging.FileHandler) and h.baseFilename == file_handler.baseFilename for h in root_logger.handlers):
             root_logger.addHandler(file_handler)
        root_logger.setLevel(log_level)


    _logging_configured = True
    # logging.info("NMS logging configured.") # Now we can use the logger

if __name__ == '__main__':
    # Example of how to use it
    setup_logging(log_level=logging.DEBUG, force_setup=True) # Use force_setup for testing this script directly
    
    # Get a logger for the current module
    logger = logging.getLogger(__name__)
    
    logger.debug("This is a debug message from logger.py.")
    logger.info("This is an info message from logger.py.")
    logger.warning("This is a warning message from logger.py.")
    logger.error("This is an error message from logger.py.")
    logger.critical("This is a critical message from logger.py.")

    # Test another module's logger (simulated)
    other_module_logger = logging.getLogger("nms.other_module")
    other_module_logger.info("Info message from a simulated other module.")

    print(f"Logging configured. Check console and the log file: {DEFAULT_LOG_FILE}")
