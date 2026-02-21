package org.xllgl2017;

public class Timeout {
    public int connect = 3000;
    public int read = 3000;
    public int write = 3000;
    public int handle = 30000;
    public int connect_times = 3;
    public int handle_times = 3;

    public void setConnect(int connect) {
        this.connect = connect;
    }

    public void setRead(int read) {
        this.read = read;
    }

    public void setWrite(int write) {
        this.write = write;
    }

    public void setHandle(int handle) {
        this.handle = handle;
    }

    public void setConnect_times(int connect_times) {
        this.connect_times = connect_times;
    }

    public void setHandle_times(int handle_times) {
        this.handle_times = handle_times;
    }


}
