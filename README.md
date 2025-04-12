# Keysight Challenge 2025

## Overclocked: Boanta Dragos-Petru, Ciobanu George-Leonard

Am implementat rutarea pentru IPv4, si am facut time profilling, am folosit parallel_reduce si parallel for.
Rezultatul se stocheaza in keysight-challenge-2025/build/src/resultX.pcap.
Pentru a da intrarea, trebuie specificat: "../../src/captureX.pcap", cu X=1, 2 sau 3. (Default este "../../src/capture<x>.pcap").
(Pentru a rula cu un test custom puteti da comanda ./build/src/gpu-router cale_catre_fisier.pcap)
Testului capture1.pcap ii corespunde result1.pcap, capture2.pcap -> result2.pcap, capture3.pcap -> result3.pcap.
Am incercat sa implementam si sa se trimita si pe socket dar din pacate nu am reusit sa l facem sa mea 
