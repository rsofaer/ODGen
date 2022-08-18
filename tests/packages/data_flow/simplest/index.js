'use strict';
// Flow 1
cp = require('child_process');
cp.spawn('ls');

// Flow 2
command = 'ls'
cp.spawn(command)

// Flow 3
command2 = 'LS'
command2 = command2.toLowerCase()
cp.spawn(command2)
