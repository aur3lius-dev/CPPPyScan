#! python2

from os import walk, path
import sys
import re
import argparse
import threading
import Queue
import copy


def parse_args():
    parser = argparse.ArgumentParser(description='Do stuff with files.',
                                     prog='cpppyscan.py',
                                     usage=('%(prog)s [-h, -r, -v, -z,'
                                            ' -e <extension(s)>, -i <filename>,'
                                            ' -o <filename>] -d|-f'
                                            ' <directory|filename>'),
                                     formatter_class=(lambda prog:
                                                      argparse.HelpFormatter(prog,
                                                                             max_help_position=65,
                                                                             width=150)))
    group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-i", "--infile", default="rules.txt", action='store_true',
                        help="File for all regex rules. Default is 'rules.txt'")
    parser.add_argument("-r", "--recursive", action='store_false',
                        help="Do not recursively search all files in the given directory")
    parser.add_argument("-e", "--extension", nargs='?', default=None,
                        help="filetype(s) to restrict search to. seperate"
                        " lists via commas with no spaces")
    parser.add_argument("-o", "--outfile", default="results.csv", nargs='?',
                        help="specify output file. Default is 'results.csv'."
                        " NOTE: will overwrite file if it currently exists")
    group.add_argument("-d", "--directory", default=None,
                       help="directory to search")
    group.add_argument("-f", "--file", default=None, help="file to search")
    parser.add_argument("-t", "--threads", default=5)
    parser.add_argument("-z", "--disableerrorhandling", action='store_true',
                        help="disable error handling to see full stack traces on errors")
    return parser.parse_args()


def main():
    progresstracker = None
    numthreads = 5
    threads = []

    args = parse_args()

    if args.infile:
        infile = args.infile

    with open(infile, 'r') as f:
        searchrules = [l.strip() for l in f if l[:3] != '#- ']

    for rule in searchrules:
        try:
            re.compile(rule)
        except re.error:
            print('[!] Invalid regex found: %s' % rule)
            exit(0)

    if args.outfile:
        outfile = args.outfile

    if args.threads:
        numthreads = int(args.threads)

    try:
        tosearch = args.directory
    except:
        tosearch = args.file

    try:
        extfilter = args.extension.split(',')
        for i, e in enumerate(extfilter):
            if e[0] == '.':
                extfilter[i] = e[1:]
    except:
        extfilter = []

    recursive = args.recursive
    errorhandling = args.disableerrorhandling

    files = findfiles(tosearch, recursive, extfilter)

    progresstracker = Progress(len(files), len(searchrules))
    progresstracker.start()

    try:
        resultdict = start(files, progresstracker, searchrules, numthreads, threads)
    except Exception as excpt:
        if not errorhandling:
            print('[!] An error ocurred:\n')
            for exc in sys.exc_info():
                print(exc)
            print(
                '[*] Note that this script may break on some filetypes when'
                ' run with 3.4. Please use 2.7')
            try:
                progresstracker.done = True
                for t in threads:
                    t.done = True
            except:
                pass
        else:
            raise excpt
        exit(-1)
    dumpresults(args.outfile, resultdict)


def start(files, prog_track, searchrules, numthreads, threads):
    filequeue = Queue.Queue()
    resqueue = Queue.Queue()
    failqueue = Queue.Queue()
    resultdict = {}

    for rule in searchrules:
        resultdict[rule] = []

    for f in files:
        filequeue.put(f)

    lock = threading.Lock()
    for i in range(numthreads):
        threads.append(Seeker(filequeue, resqueue, failqueue,
                              searchrules, prog_track, lock, i))
        threads[i].start()

    [t.join() for t in threads]
    prog_track.done = True
    prog_track.join()

    if not failqueue.empty():
        print('[!] Unable to open the following files:')
        while not failqueue.empty():
            print('\t%s' % failqueue.get())
        print('')

    while not resqueue.empty():
        newdict = resqueue.get()
        for k, v in newdict.iteritems():
            resultdict[k].extend(v)

    return resultdict


def linecount(files):
    count = 0
    for file in files:
        with open(file, 'r') as f:
            count += sum([1 for l in f])

    return count


def findfiles(i_dir, recursive, extfilter):
    flist = []

    if path.isdir(i_dir):
        for (dirpath, _, filenames) in walk(i_dir):
            flist.extend(['%s/%s' % (dirpath, filename)
                          for filename in filenames])
            if not recursive:
                break

        if len(extfilter) > 0:
            for f in flist:
                if f.split('.')[-1] in extfilter:
                    flist.remove(f)
    else:
        flist = [i_dir]
    return flist


def dumpresults(outfile, resultdict):
    if outfile is None:
        outfile = 'results.csv'
    with open(outfile, 'w') as f:
        for key, values in resultdict.iteritems():
            f.write('%s\n' % key)
            for value in values:
                f.write('%s\n' % value)
    print('Results saved to: %s' % outfile)


class Seeker(threading.Thread):

    def __init__(self, filequeue, r_queue, f_queue, s_rules, p_track, lock, s_id):
        threading.Thread.__init__(self)
        self.filequeue = filequeue
        self.resqueue = r_queue
        self.failqueue = f_queue
        # not entirely sure if this is required, but just in case...
        self.searchrules = copy.deepcopy(s_rules)
        self.progresstracker = p_track
        self.lock = lock
        self.done = False
        self.id = s_id

        self.resultdict = {}
        for rule in self.searchrules:
            self.resultdict[rule] = []

    def run(self):
        while not self.done and not self.filequeue.empty():
            try:
                self.searchfile(self.filequeue.get(timeout=0.1))
            except Queue.Empty:
                pass
            except IOError:  # Ignores the file if it is unavailable.
                pass
        self.done = True

    def searchfile(self, file):
        self.cleardict()

        try:
            with open(file) as f:
                for rule in self.searchrules:
                    linenum = 1
                    f.seek(0)
                    prog = re.compile(rule, flags=re.IGNORECASE)
                    for l in f:
                        if prog.search(l):
                            # formatting done for csv rfc purposes
                            self.resultdict[rule].append('"%s","%s","%s"' %
                                                         (file.replace('"', '""'),
                                                          linenum,
                                                          l.strip().replace('"', '""')))
                        linenum += 1
                    self.lock.acquire()
                    self.progresstracker.checksdone += 1
                    self.lock.release()
            # deep copy to make sure we don't have threads messing with
            # multiple refs to the same dict
            self.resqueue.put(copy.deepcopy(self.resultdict))
        except IOError:
            self.lock.acquire()
            self.progresstracker.checksdone += len(self.searchrules)
            self.lock.release()
            self.failqueue.put(file)

    def cleardict(self):
        for k, _ in self.resultdict.iteritems():
            self.resultdict[k] = []

    def __repr__(self):
        print('<ID: %s>' % self.id)


class Progress(threading.Thread):

    def __init__(self, numfiles, numrules):
        threading.Thread.__init__(self)
        self.numchecks = float(numfiles * numrules)
        self.checksdone = 0.0
        self.done = False

    def run(self):
        while not self.done:
            progress = self.checksdone / self.numchecks
            barLength = 20
            if isinstance(progress, int):
                progress = float(progress)
            if progress >= 1:
                progress = 1
            block = int(round(barLength * progress))
            text = "\r[{0}] {1:.2f}%".format(
                "#" * block + "-" * (barLength - block), progress * 100)
            sys.stdout.write(text)
            sys.stdout.flush()

        print('\n')

if __name__ == "__main__":
    main()
