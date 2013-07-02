#include "harvester.h"
#include "log_macros.h"
#include <sys/inotify.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

static int _SetNonBlock(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) < 0)
    {
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) < 0)
    {
        return -1;
    }

    return 0;
}

LogHarvester::LogHarvester()
{
    inotify_ = -1;
}

int LogHarvester::create()
{
    inotify_ = inotify_init();
    if (inotify_ < 0)
    {
        L_ERROR("inotify_init error %d", errno);
        return -1;
    }

    _SetNonBlock(inotify_);
    return 0;
}

int LogHarvester::add_watch( const std::string& fn )
{
    int fd = inotify_add_watch(inotify_, fn.c_str(), IN_MODIFY|IN_DELETE_SELF|IN_MOVE_SELF);
    if (fd < 0)
    {
        L_ERROR("add watch %s error %d", fn.c_str(), errno);
        return -1;
    }

    Watcher& w = watchers_[fd];
    w.fd_ = fd;
    w.filename_ = fn;
    w.last_event_time_ = time(NULL);
    int rdfd = open(fn.c_str(), O_RDONLY);
    if (rdfd < 0)
    {
        L_ERROR("open %s errno %d", w.filename_.c_str(), errno);
        return fd;
    }

    struct stat file_stat;
    int err = fstat(rdfd, &file_stat);
    if (err == 0)
    {
        w.prev_offset_ = file_stat.st_size;
    }

    close(rdfd);
    return fd;
}

int LogHarvester::event_check()
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(inotify_, &rfds);
    timeval timeout = {0, 0};
    int ret = select(inotify_+1, &rfds, NULL, NULL, &timeout);
    if (ret > 0)
    {
        char rd_buf[1024];
        int r;
        int rdoffset = 0, poffset, peventlen;
        inotify_event *pevent;

        while (true)
        {
            r = read(inotify_, &rd_buf[rdoffset], sizeof(rd_buf)-rdoffset);
            if (r <= 0)
            {
                if (r < 0 && errno != EAGAIN)
                {
                    L_ERROR("ready inotify fd error %d", errno);
                }

                break;
            }

            poffset = 0;
            while (poffset < r)
            {
                pevent = (inotify_event *)&rd_buf[poffset];
                peventlen = pevent->len + sizeof(inotify_event);
                if (r - poffset >= peventlen)
                {
                    //read newline from this file
                    //if not newline, skip
                    //event handler(node_name, contentline)
                    if (pevent->mask & IN_MODIFY)
                    {
                        // read last line
                        L_INFO("write event from fd %d", pevent->wd);
                        read_new_log(pevent->wd);
                    }

                    if (pevent->mask & IN_DELETE_SELF)
                    {
                        L_INFO("delete event from fd %d", pevent->wd);
                        inotify_rm_watch(inotify_, pevent->wd);
                        watchers_.erase(pevent->wd);
                    }

                    if (pevent->mask & IN_MOVE_SELF)
                    {
                        L_INFO("file is moved, fd %d", pevent->wd);
                        inotify_rm_watch(inotify_, pevent->wd);
                        watchers_.erase(pevent->wd);
                    }

                    poffset += peventlen;
                }
                else
                {
                    memmove(rd_buf, &rd_buf[poffset], r-poffset);
                    rdoffset = r-poffset;
                    break;
                }
            }
        }
    }
    else if (ret < 0)
    {
        L_ERROR("select inotify failed, errno %d", errno);
        return -1;
    }

    return 0;
}

void LogHarvester::read_new_log( int fd )
{
    fd2watcher_map_t::iterator it = watchers_.find(fd);
    if (it == watchers_.end())
    {
        return;
    }

    Watcher& w = it->second;
    w.last_event_time_ = time(NULL);
    int rdfd = open(w.filename_.c_str(), O_RDONLY);
    if (rdfd < 0)
    {
        L_ERROR("open %s errno %d", w.filename_.c_str(), errno);
        return;
    }

    // NOTE: close rdfd before return
    _SetNonBlock(rdfd);
    struct stat file_stat;
    int err = fstat(rdfd, &file_stat);
    if (err < 0)
    {
        L_ERROR("fstat %d error %d", rdfd, errno);
        close(rdfd);
        return;
    }

    if (file_stat.st_size < w.prev_offset_ || 0 == w.prev_offset_)
    {
        // file may be truncated
        w.prev_offset_ = file_stat.st_size;
        close(rdfd);
        return;
    }

    string linebuf;
    char rdbuf[1024];
    int r;
    size_t delim_pos;
    err = lseek(rdfd, w.prev_offset_, SEEK_SET);
    while (true)
    {
        r = read(rdfd, rdbuf, sizeof(rdbuf));
        if (r <= 0)
        {
            if (0 == r || errno == EAGAIN) break;
            if (errno == EINTR) continue;
        }

        linebuf.append(rdbuf, r);
    }

    close(rdfd);

    int linebuf_off = 0;
    int log_len;
    do 
    {
        delim_pos = linebuf.find("\n", linebuf_off);
        if (delim_pos == string::npos) break;
        log_len = delim_pos-linebuf_off;
        if (callback_)
        {
            callback_(w.filename_, linebuf.substr(linebuf_off, log_len));
        }
        
        linebuf_off += log_len+1;
    } while (string::npos != delim_pos);

    w.prev_offset_ += linebuf_off;
}

void LogHarvester::clear_watchers()
{
    for (fd2watcher_map_t::iterator it = watchers_.begin(); it != watchers_.end(); )
    {
        inotify_rm_watch(inotify_, it->second.fd_);
        watchers_.erase(it++);
    }
}

void LogHarvester::remove_watcher( int wd )
{
    fd2watcher_map_t::iterator it = watchers_.find(wd);
    if (it != watchers_.end())
    {
        watchers_.erase(it);
    }

    inotify_rm_watch(inotify_, wd);
}

time_t LogHarvester::get_last_event_time( int wd )
{
    fd2watcher_map_t::iterator it = watchers_.find(wd);
    if (it == watchers_.end())
    {
        return 0;
    }

    return it->second.last_event_time_;
}
