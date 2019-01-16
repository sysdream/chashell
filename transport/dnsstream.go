package transport

import "fmt"

type dnsStream struct {

}

func DNSStream() *dnsStream {
	go Recv()
	return &dnsStream{}
}

func (w *dnsStream) Write(data []byte)(int, error) {
	return Send(data)
}

func (r *dnsStream) Read(data []byte)(int, error){
	return Read(data)
}

func Read(output []byte)(int, error){
	if packetQueue.Len() > 0 {
		data := packetQueue.Front()
		stringData := fmt.Sprintf("%s", data.Value)
		copy(output, stringData)
		packetQueue.Remove(data)
		return len(stringData), nil
	}
	return 0, nil
}

