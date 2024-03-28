from utils.Spinner import Spinner, Modes
from time import sleep
from tqdm import tqdm

modes = [
    Modes.Arc,
    Modes.Arrow,
    Modes.BouncingBar,
    Modes.H_Lines,
    Modes.Lines,
    Modes.Pong,
    Modes.RoundBounce5,
    Modes.RoundBounce6,
    Modes.SquareBounce5,
    Modes.SquareBounce6,
]

for mode in modes:
    with Spinner(mode=mode, suffix=' Working...'):
        for i in range(5):
            sleep(1)