"use client"

import { Server, Database, Cloud, Shield, Lock, Zap } from "lucide-react"

export function InfrastructureProtection() {
  const protectionLayers = [
    {
      icon: Cloud,
      title: "Edge Protection",
      description: "First line of defense at the network edge",
      coverage: "Global CDN with 200+ PoPs",
    },
    {
      icon: Shield,
      title: "Application Layer",
      description: "Web application firewall and API protection",
      coverage: "OWASP Top 10 + Zero-day protection",
    },
    {
      icon: Server,
      title: "Infrastructure Layer",
      description: "Server and network infrastructure security",
      coverage: "DDoS mitigation + Intrusion detection",
    },
    {
      icon: Database,
      title: "Data Layer",
      description: "Database security and encryption",
      coverage: "End-to-end encryption + Access control",
    },
  ]

  const infrastructureTypes = [
    {
      icon: Server,
      title: "Government Portals",
      description: "Protecting citizen services and government websites from cyber threats",
      threats: ["DDoS attacks", "Data breaches", "Service disruption"],
      protection: "99.99% uptime guarantee",
    },
    {
      icon: Database,
      title: "Financial Systems",
      description: "Securing banking and financial infrastructure against sophisticated attacks",
      threats: ["Transaction fraud", "Data theft", "System compromise"],
      protection: "PCI DSS compliance",
    },
    {
      icon: Cloud,
      title: "Public Services",
      description: "Ensuring continuous availability of critical public service platforms",
      threats: ["Service outages", "Data corruption", "Unauthorized access"],
      protection: "Multi-layer redundancy",
    },
  ]

  return (
    <section className="relative py-20 z-10">
      <div className="container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="text-4xl font-bold text-green-400 mb-4 font-mono">INFRASTRUCTURE PROTECTION</h2>
          <p className="text-green-200 text-lg max-w-3xl mx-auto">
            Comprehensive multi-layer security architecture designed to protect critical national infrastructure from
            sophisticated cyber threats and nation-state attacks.
          </p>
        </div>

        {/* Protection Layers */}
        <div className="mb-16">
          <h3 className="text-2xl font-bold text-green-400 mb-8 text-center font-mono">DEFENSE LAYERS</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
            {protectionLayers.map((layer, index) => (
              <div key={index} className="relative">
                <div className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm hover:border-green-400/50 transition-all duration-300 h-full">
                  <layer.icon className="w-12 h-12 text-green-400 mx-auto mb-4" />
                  <h4 className="text-lg font-bold text-green-400 text-center mb-3 font-mono">{layer.title}</h4>
                  <p className="text-green-200 text-sm text-center mb-4">{layer.description}</p>
                  <div className="text-xs text-green-300 text-center bg-gray-900/50 rounded p-2">{layer.coverage}</div>
                </div>
                {index < protectionLayers.length - 1 && (
                  <div className="hidden md:block absolute top-1/2 -right-3 w-6 h-0.5 bg-green-500 z-10" />
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Infrastructure Types */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {infrastructureTypes.map((type, index) => (
            <div
              key={index}
              className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm hover:border-green-400/50 transition-all duration-300"
            >
              <div className="flex items-center mb-4">
                <type.icon className="w-8 h-8 text-green-400 mr-3" />
                <h4 className="text-xl font-bold text-green-400 font-mono">{type.title}</h4>
              </div>

              <p className="text-green-200 mb-6">{type.description}</p>

              <div className="mb-6">
                <h5 className="text-sm font-bold text-green-400 mb-3 font-mono">COMMON THREATS:</h5>
                <div className="space-y-2">
                  {type.threats.map((threat, threatIndex) => (
                    <div key={threatIndex} className="flex items-center text-sm text-red-300">
                      <Zap className="w-3 h-3 mr-2" />
                      {threat}
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-green-900/20 border border-green-500/30 rounded p-3">
                <div className="flex items-center text-green-400">
                  <Lock className="w-4 h-4 mr-2" />
                  <span className="text-sm font-mono">{type.protection}</span>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Security Standards */}
        <div className="mt-16 bg-black/70 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm">
          <h3 className="text-2xl font-bold text-green-400 mb-6 text-center font-mono">COMPLIANCE & STANDARDS</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {[
              "ISO 27001",
              "SOC 2 Type II",
              "NIST Framework",
              "FedRAMP",
              "PCI DSS",
              "GDPR Compliant",
              "HIPAA Ready",
              "Common Criteria",
            ].map((standard, index) => (
              <div key={index} className="bg-gray-900/50 rounded p-3 text-center">
                <div className="text-green-400 font-mono font-bold">{standard}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}
