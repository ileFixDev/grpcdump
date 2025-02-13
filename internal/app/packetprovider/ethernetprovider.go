package packetprovider

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rmedvedev/grpcdump/internal/app/filter"
)

// EthernetProvider handles ethernet packet capture
type EthernetProvider struct {
	handler *pcap.Handle
}

// NewEthernetProvider creates a new EthernetProvider
func NewEthernetProvider(iface string) (PacketProvider, error) {
	// Open the device in promiscuous mode
	handler, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	return &EthernetProvider{handler}, nil
}

// SetFilter sets BPF filter
func (provider *EthernetProvider) SetFilter(packetFilter *filter.PacketFilter) error {
	rawInstructions := packetFilter.GetBpfFilter()
	// Convert []bpf.RawInstruction to []pcap.BPFInstruction
	instructions := make([]pcap.BPFInstruction, len(rawInstructions))
	for i, raw := range rawInstructions {
		instructions[i] = pcap.BPFInstruction{
			Code: raw.Op,
			Jt:   raw.Jt,
			Jf:   raw.Jf,
			K:    raw.K,
		}
	}
	return provider.handler.SetBPFInstructionFilter(instructions)
}

// GetPackets returns a channel for receiving packets
func (provider *EthernetProvider) GetPackets() chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(provider.handler, layers.LayerTypeEthernet)
	return packetSource.Packets()
}

// Close closes the packet capture handle
func (provider *EthernetProvider) Close() {
	if provider.handler != nil {
		provider.handler.Close()
	}
}
