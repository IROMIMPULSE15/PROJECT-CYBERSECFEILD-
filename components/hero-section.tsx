"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Shield, Zap, Globe, Lock, ArrowRight } from "lucide-react"

export function HeroSection() {
  const [typedText, setTypedText] = useState("")
  const [currentIndex, setCurrentIndex] = useState(0)
  const fullText = "DEFENDING NATIONAL WEB INFRASTRUCTURE"

  useEffect(() => {
    if (currentIndex < fullText.length) {
      const timeout = setTimeout(() => {
        setTypedText((prev) => prev + fullText[currentIndex])
        setCurrentIndex((prev) => prev + 1)
      }, 100)
      return () => clearTimeout(timeout)
    }
  }, [currentIndex, fullText])

  return (
    <section className="relative min-h-screen flex items-center justify-center z-10">
      <div className="container mx-auto px-6 text-center">
        <div className="mb-8">
          <div className="inline-flex items-center space-x-4 mb-6">
            <Shield className="w-16 h-16 text-green-400 animate-pulse" />
            <div className="text-6xl font-bold text-green-400 font-mono tracking-wider">CYBERDEFENSE</div>
          </div>

          <div className="text-2xl font-mono text-green-300 mb-4 h-8">
            {typedText}
            <span className="animate-pulse">|</span>
          </div>

          <p className="text-lg text-green-200 max-w-4xl mx-auto leading-relaxed">
            Advanced AI-powered security platform protecting government websites, financial portals, and critical
            infrastructure from coordinated cyberattacks, DDoS threats, and data exfiltration.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mt-12">
          {[
            { icon: Shield, label: "DDoS Protection", value: "99.9%" },
            { icon: Zap, label: "Response Time", value: "<1ms" },
            { icon: Globe, label: "Global Coverage", value: "200+" },
            { icon: Lock, label: "Threats Blocked", value: "1M+" },
          ].map((stat, index) => (
            <div
              key={index}
              className="bg-black/50 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm hover:border-green-400/50 transition-all duration-300"
            >
              <stat.icon className="w-8 h-8 text-green-400 mx-auto mb-3" />
              <div className="text-3xl font-bold text-green-400 font-mono">{stat.value}</div>
              <div className="text-green-300 text-sm">{stat.label}</div>
            </div>
          ))}
        </div>

        <div className="mt-12 space-x-4">
          <Link
            href="/dashboard"
            className="inline-flex items-center space-x-2 bg-green-600 hover:bg-green-500 text-black font-bold py-4 px-8 rounded-lg transition-all duration-300 transform hover:scale-105 shadow-lg shadow-green-500/25"
          >
            <span>DEPLOY PROTECTION</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            href="/pricing"
            className="inline-flex items-center space-x-2 border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-4 px-8 rounded-lg transition-all duration-300"
          >
            <span>VIEW PLANS</span>
          </Link>
        </div>
      </div>
    </section>
  )
}
