#include "sniffer.h"

int main(int argc, char* argv[]){

    // Create an instance of Arguments and parse the command line arguments
    Arguments args(argc, argv);

    // Dynamically allocate a PacketSniffer object
    PacketSniffer* sniffer = new PacketSniffer(args);

    // Start sniffing
    sniffer->start_sniffing();

    // Clean up
    delete sniffer;

    
    return 0;
}