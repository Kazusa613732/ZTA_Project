#!/bin/bash

# 同時啟動兩個 nodemon 程式
nodemon ./index.js &
nodemon ./protected.js &

# 等待所有背景程序執行完畢
wait
