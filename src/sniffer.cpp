/**
 * @file sniffer.cpp
 * @author David Skalka (xskalk03@stud.fit.vutbr.cz)
 * 
 * @brief File containting main function for ipk-sniffer
 * 
 * @version 0.1
 * @date 2024-04-22
 * 
 * @copyright Copyright (c) 2024
 * 
 */

#include "sniffer.h"

int main(int argc, char* argv[]){

    // Create an instance of Arguments and parse the command line arguments
    Arguments args(argc, argv);

    // Dynamically allocate a PacketSniffer object
    PacketSniffer* sniffer = new PacketSniffer(args);

    // Start sniffing
    sniffer->start_sniffing();

    if(sigint_received.load()){
        delete sniffer;
        return 0;
    }

    // Clean up
    delete sniffer;


    return 0;
}