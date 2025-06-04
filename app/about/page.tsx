"use client"

import { Navigation } from "@/components/navigation"
import { ParticleBackground } from "@/components/particle-background"
import { Footer } from "@/components/footer"
import { Shield, Users, Globe, Award, Target, Eye, Lock } from "lucide-react"

export default function AboutPage() {
  const stats = [
    { icon: Shield, label: "Threats Blocked", value: "10M+", color: "text-red-400" },
    { icon: Users, label: "Protected Organizations", value: "5,000+", color: "text-blue-400" },
    { icon: Globe, label: "Global Locations", value: "200+", color: "text-green-400" },
    { icon: Award, label: "Uptime Guarantee", value: "99.99%", color: "text-yellow-400" },
  ]

  const team = [
    {
      name: "Dr. Sarah Chen",
      role: "Chief Security Officer",
      background: "Former NSA Cybersecurity Director",
      image: "/placeholder.svg?height=200&width=200",
    },
    {
      name: "Marcus Rodriguez",
      role: "Head of Threat Intelligence",
      background: "Ex-FBI Cyber Division",
      image: "/placeholder.svg?height=200&width=200",
    },
    {
      name: "Dr. Aisha Patel",
      role: "AI Research Director",
      background: "MIT AI Lab, DARPA Consultant",
      image: "/placeholder.svg?height=200&width=200",
    },
    {
      name: "James Thompson",
      role: "Infrastructure Security Lead",
      background: "Former Pentagon IT Security",
      image: "/placeholder.svg?height=200&width=200",
    },
  ]

  const values = [
    {
      icon: Target,
      title: "Mission Critical",
      description: "We understand that your infrastructure is vital to national security and public safety.",
    },
    {
      icon: Eye,
      title: "Constant Vigilance",
      description: "24/7 monitoring and threat detection ensures your systems are always protected.",
    },
    {
      icon: Lock,
      title: "Zero Trust",
      description: "We verify everything and trust nothing, providing the highest level of security.",
    },
  ]

  return (
    <div className="min-h-screen bg-black text-green-400">
      <ParticleBackground />
      <Navigation />

      <div className="pt-20 pb-16">
        <div className="container mx-auto px-6">
          {/* Hero Section */}
          <div className="text-center mb-16">
            <h1 className="text-4xl font-bold text-green-400 mb-4 font-mono">ABOUT CYBERDEFENSE</h1>
            <p className="text-green-200 text-lg max-w-4xl mx-auto leading-relaxed">
              Founded by cybersecurity veterans and backed by government agencies, CyberDefense is the premier platform
              for protecting critical national infrastructure from sophisticated cyber threats and nation-state attacks.
            </p>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-16">
            {stats.map((stat, index) => (
              <div
                key={index}
                className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center"
              >
                <stat.icon className={`w-12 h-12 ${stat.color} mx-auto mb-4`} />
                <div className={`text-3xl font-bold font-mono ${stat.color} mb-2`}>{stat.value}</div>
                <div className="text-green-300">{stat.label}</div>
              </div>
            ))}
          </div>

          {/* Mission */}
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm mb-16">
            <h2 className="text-3xl font-bold text-green-400 mb-6 text-center font-mono">OUR MISSION</h2>
            <p className="text-green-200 text-lg leading-relaxed text-center max-w-4xl mx-auto">
              To provide unbreakable cybersecurity solutions that protect the digital infrastructure powering our
              society. We combine cutting-edge AI technology with human expertise to create an impenetrable shield
              against cyber threats, ensuring the continuity of critical services that millions depend on every day.
            </p>
          </div>

          {/* Values */}
          <div className="mb-16">
            <h2 className="text-3xl font-bold text-green-400 mb-8 text-center font-mono">CORE VALUES</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {values.map((value, index) => (
                <div
                  key={index}
                  className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center"
                >
                  <value.icon className="w-12 h-12 text-green-400 mx-auto mb-4" />
                  <h3 className="text-xl font-bold text-green-400 mb-3 font-mono">{value.title}</h3>
                  <p className="text-green-200">{value.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Leadership Team */}
          <div className="mb-16">
            <h2 className="text-3xl font-bold text-green-400 mb-8 text-center font-mono">LEADERSHIP TEAM</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
              {team.map((member, index) => (
                <div
                  key={index}
                  className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm text-center"
                >
                  <div className="w-24 h-24 bg-gray-800 rounded-full mx-auto mb-4 flex items-center justify-center">
                    <Users className="w-12 h-12 text-green-400" />
                  </div>
                  <h3 className="text-lg font-bold text-green-400 mb-2 font-mono">{member.name}</h3>
                  <p className="text-green-300 text-sm mb-2">{member.role}</p>
                  <p className="text-green-200 text-xs">{member.background}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Technology */}
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm">
            <h2 className="text-3xl font-bold text-green-400 mb-6 text-center font-mono">ADVANCED TECHNOLOGY</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div>
                <h3 className="text-xl font-bold text-green-400 mb-4 font-mono">AI-Powered Defense</h3>
                <p className="text-green-200 mb-4">
                  Our neural networks analyze billions of data points in real-time, identifying and neutralizing threats
                  before they can impact your infrastructure.
                </p>
                <ul className="space-y-2">
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    Machine learning threat detection
                  </li>
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    Behavioral analysis algorithms
                  </li>
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    Predictive threat modeling
                  </li>
                </ul>
              </div>
              <div>
                <h3 className="text-xl font-bold text-green-400 mb-4 font-mono">Global Infrastructure</h3>
                <p className="text-green-200 mb-4">
                  Our distributed network spans the globe, providing low-latency protection and ensuring your services
                  remain available even under the most severe attacks.
                </p>
                <ul className="space-y-2">
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    200+ edge locations worldwide
                  </li>
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    10+ Tbps DDoS mitigation capacity
                  </li>
                  <li className="flex items-center text-green-300">
                    <div className="w-2 h-2 bg-green-400 rounded-full mr-3"></div>
                    Sub-millisecond response times
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  )
}
