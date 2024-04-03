#include "sniffer.h"

int main(int argc, char* argv[]){

    // Create an instance of Arguments and parse the command line arguments
    Arguments args(argc, argv);

    PacketSniffer sniffer(args);
    sniffer.start_sniffing();

    return 0;
}