from werkzeug.utils import secure_filename
import logging

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename: str) -> bool:
    result = '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    if not result:
        logger.warning(f"File '{filename}' has disallowed extension.")
    return result
