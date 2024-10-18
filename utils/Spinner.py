import sys
import time
import threading

class Modes:
    Arc = [
        '◜',
        '◝',
        '◞',
        '◟'
    ]

    Arrow = [
        "▹▹▹▹▹",
        "▸▹▹▹▹",
        "▹▸▹▹▹",
        "▹▹▸▹▹",
        "▹▹▹▸▹",
        "▹▹▹▹▸"
    ]

    BouncingBar = [
        "[    ]",
        "[=   ]",
        "[==  ]",
        "[=== ]",
        "[ ===]",
        "[  ==]",
        "[   =]",
        "[    ]",
        "[   =]",
        "[  ==]",
        "[ ===]",
        "[====]",
        "[=== ]",
        "[==  ]",
        "[=   ]"
    ]

    Lines = [
        '|',
        '/',
        '-',
        '\\'
    ]

    H_Lines = [
            '-',
            '=',
            '≡',
            '='
        ]

    Pong = [
        "▐⠂       ▌",
        "▐⠈       ▌",
        "▐ ⠂      ▌",
        "▐ ⠠      ▌",
        "▐  ⡀     ▌",
        "▐  ⠠     ▌",
        "▐   ⠂    ▌",
        "▐   ⠈    ▌",
        "▐    ⠂   ▌",
        "▐    ⠠   ▌",
        "▐     ⡀  ▌",
        "▐     ⠠  ▌",
        "▐      ⠂ ▌",
        "▐      ⠈ ▌",
        "▐       ⠂▌",
        "▐       ⠠▌",
        "▐       ⡀▌",
        "▐      ⠠ ▌",
        "▐      ⠂ ▌",
        "▐     ⠈  ▌",
        "▐     ⠂  ▌",
        "▐    ⠠   ▌",
        "▐    ⡀   ▌",
        "▐   ⠠    ▌",
        "▐   ⠂    ▌",
        "▐  ⠈     ▌",
        "▐  ⠂     ▌",
        "▐ ⠠      ▌",
        "▐ ⡀      ▌",
        "▐⠠       ▌"
    ]

    RoundBounce6 = [
        '( ●    )',
        '(  ●   )',
        '(   ●  )',
        '(    ● )',
        '(     ●)',
        '(    ● )',
        '(   ●  )',
        '(  ●   )',
        '( ●    )',
        '(●     )'
    ]

    RoundBounce5 = [
        '(●    )',
        '( ●   )',
        '(  ●  )',
        '(   ● )',
        '(    ●)',
        '(   ● )',
        '(  ●  )',
        '( ●   )'
    ]

    SquareBounce5 = [
        '[▪    ]',
        '[ ▪   ]',
        '[  ▪  ]',
        '[   ▪ ]',
        '[    ▪]',
        '[   ▪ ]',
        '[  ▪  ]',
        '[ ▪   ]'
    ]

    SquareBounce6 = [
        '[▪     ]',
        '[ ▪    ]',
        '[  ▪   ]',
        '[   ▪  ]',
        '[    ▪ ]',
        '[     ▪]',
        '[    ▪ ]',
        '[   ▪  ]',
        '[  ▪   ]',
        '[ ▪    ]'
    ]

class Spinner:
    busy = False
    delay = 0.1

    @staticmethod
    def spinning_cursor(frames,suffix):
        while 1:
            for cursor in frames: yield f'{cursor}{suffix}'

    def __init__(self, delay=None, mode=Modes.RoundBounce5, suffix=''):
        self.frames=mode
        self.suffix=suffix
        self.spinner_generator = self.spinning_cursor(self.frames,self.suffix)
        if delay and float(delay): self.delay = delay

    def spinner_task(self):
        while self.busy:
            sys.stdout.write(next(self.spinner_generator))
            sys.stdout.flush()
            time.sleep(self.delay)
            sys.stdout.write('\b' * (len(self.frames[0]) + len(self.suffix)))
            sys.stdout.flush()

    def __enter__(self):
        self.busy = True
        threading.Thread(target=self.spinner_task).start()

    def __exit__(self, exception, value, tb):
        self.busy = False
        time.sleep(self.delay)
        sys.stdout.write('\b' * (len(self.frames[0]) + len(self.suffix)))
        sys.stdout.flush()
        print(f'{" " * (len(self.frames[0])+ len(self.suffix))}\033[A') 
        # print spaces where the spinner was, then place the cursor at 
        # the beginning of previous line so next line of output will
        # overwrite the spaces
        if exception is not None:
            return False

