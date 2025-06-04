"use client"

import { Shield, Lock, Eye, Zap, Brain, Globe } from "lucide-react"

export function SecurityFeatures() {
  const features = [
    {
      icon: Shield,
      title: "DDoS Protection",
      description:
        "Advanced multi-layer DDoS mitigation protecting against volumetric, protocol, and application layer attacks.",
      specs: ["10+ Tbps capacity", "Sub-second detection", "Global anycast network"],
    },
    {
      icon: Brain,
      title: "AI Threat Intelligence",
      description:
        "Machine learning algorithms analyze traffic patterns to identify and block sophisticated attack vectors.",
      specs: ["Neural network analysis", "Behavioral detection", "Zero-day protection"],
    },
    {
      icon: Lock,
      title: "Zero Trust Architecture",
      description: "Never trust, always verify. Comprehensive identity verification for every request and user.",
      specs: ["Identity verification", "Micro-segmentation", "Continuous monitoring"],
    },
    {
      icon: Eye,
      title: "Deep Packet Inspection",
      description:
        "Real-time analysis of network traffic at the packet level to detect malicious content and anomalies.",
      specs: ["Layer 7 inspection", "Content filtering", "Protocol analysis"],
    },
    {
      icon: Zap,
      title: "Instant Response",
      description: "Automated threat response with millisecond reaction times to neutralize attacks before impact.",
      specs: ["<1ms response time", "Automated mitigation", "Real-time blocking"],
    },
    {
      icon: Globe,
      title: "Global Edge Network",
      description:
        "Distributed security infrastructure across 200+ locations worldwide for maximum protection coverage.",
      specs: ["200+ edge locations", "99.99% uptime", "Global load balancing"],
    },
  ]

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">ADVANCED SECURITY FEATURES</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Military-grade security technologies designed to protect critical infrastructure from the most sophisticated
            cyber threats and nation-state attacks.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {features.map((feature, index) => (
            <div
              key={index}
              className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm hover:border-green-400/50 transition-all duration-300 group hover:transform hover:scale-105"
            >
              <div className="flex items-center mb-4">
                <feature.icon className="w-8 h-8 text-green-400 mr-3 group-hover:animate-pulse" />
                <h3 className="text-xl font-bold text-green-400 font-mono">{feature.title}</h3>
              </div>

              <p className="text-green-200 mb-4 leading-relaxed">{feature.description}</p>

              <div className="space-y-2">
                {feature.specs.map((spec, specIndex) => (
                  <div key={specIndex} className="flex items-center text-sm text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3" />
                    {spec}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
