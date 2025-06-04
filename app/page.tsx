"use client"

import { ParticleBackground } from "@/components/particle-background"
import { Navigation } from "@/components/navigation"
import { HeroSection } from "@/components/hero-section"
import { ThreatDetection } from "@/components/threat-detection"
import { SecurityFeatures } from "@/components/security-features"
import { TrustMetrics } from "@/components/trust-metrics"
import { Footer } from "@/components/footer"

export default function Home() {
  return (
    <div className="min-h-screen bg-black text-green-400 overflow-x-hidden">
      <ParticleBackground />
      <Navigation />
      <HeroSection />
      <ThreatDetection />
      <SecurityFeatures />
      <TrustMetrics />
      <Footer />
    </div>
  )
}
