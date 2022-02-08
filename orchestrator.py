import subprocess
import logging
from datetime import datetime



if __name__ == '__main__':

    # Define logger

    logger = logging.getLogger(__name__)

    # Set logging level
    logger.setLevel(logging.INFO)

    # define file handler and set formatter
    file_handler = logging.FileHandler('logs/orchestrator{:%Y-%m-%d}.log'.format(datetime.now()))
    formatter = logging.Formatter('%(asctime)s : %(levelname)s : %(name)s : %(message)s')
    file_handler.setFormatter(formatter)
    # add file handler to logger
    logger.addHandler(file_handler)

    try:
        p1 = subprocess.Popen(['python3', 'clientCount.py'])
        logger.info('Client Count ran success!')
    except Exception as e:
        logger.info(f'Client Count failed! {e}')
    # try:
    #     p2 = subprocess.Popen(['python3', 'userDetails.py'])
    #     logger.info('Client Details ran success!')
    # except Exception as e:
    #     logger.info(f'Client Details failed! {e}')
    p1.wait()
