if [ $(id -u) == 0 ]; then
    COLOR="31"
else
    COLOR="34"
    cd /home/user
fi
export PS1="\e[01;${COLOR}m$(whoami)@sctf\[\033[00m\]:\[\033[36m\]\w\[\033[00m\]\$ "
