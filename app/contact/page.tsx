"use client"

import type React from "react"

import { useState } from "react"
import { Navigation } from "@/components/navigation"
import { ParticleBackground } from "@/components/particle-background"
import { Footer } from "@/components/footer"
import { Mail, Phone, MapPin, Clock, Send, Shield } from "lucide-react"
import { useToast } from "@/hooks/use-toast"

export default function ContactPage() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    organization: "",
    subject: "",
    message: "",
    urgency: "normal",
  })
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)

    // Simulate form submission
    await new Promise((resolve) => setTimeout(resolve, 2000))

    toast({
      title: "Message Sent",
      description: "Our security team will respond within 24 hours.",
    })

    setFormData({
      name: "",
      email: "",
      organization: "",
      subject: "",
      message: "",
      urgency: "normal",
    })
    setLoading(false)
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }))
  }

  const contactInfo = [
    {
      icon: Mail,
      title: "Email Support",
      details: "security@cyberdefense.gov",
      description: "24/7 security incident response",
    },
    {
      icon: Phone,
      title: "Emergency Hotline",
      details: "+1 (555) CYBER-SEC",
      description: "Critical threat response",
    },
    {
      icon: MapPin,
      title: "Headquarters",
      details: "1600 Cyber Defense Way, Washington DC",
      description: "Secure operations center",
    },
    {
      icon: Clock,
      title: "Response Time",
      details: "< 1 hour for critical threats",
      description: "Guaranteed SLA response",
    },
  ]

  return (
    <div className="min-h-screen bg-black text-green-400">
      <ParticleBackground />
      <Navigation />

      <div className="pt-20 pb-16">
        <div className="container mx-auto px-6">
          {/* Header */}
          <div className="text-center mb-16">
            <h1 className="text-4xl font-bold text-green-400 mb-4 font-mono">SECURE CONTACT</h1>
            <p className="text-green-200 text-lg max-w-3xl mx-auto">
              Reach out to our cybersecurity experts for immediate assistance, threat reporting, or to discuss your
              organization's security requirements.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12">
            {/* Contact Form */}
            <div className="bg-black/70 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm">
              <div className="flex items-center mb-6">
                <Shield className="w-6 h-6 text-green-400 mr-3" />
                <h2 className="text-2xl font-bold text-green-400 font-mono">SEND SECURE MESSAGE</h2>
              </div>

              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-green-400 text-sm font-mono mb-2">NAME *</label>
                    <input
                      type="text"
                      name="name"
                      value={formData.name}
                      onChange={handleChange}
                      className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                      placeholder="John Doe"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-green-400 text-sm font-mono mb-2">EMAIL *</label>
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleChange}
                      className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                      placeholder="john@organization.gov"
                      required
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-green-400 text-sm font-mono mb-2">ORGANIZATION</label>
                  <input
                    type="text"
                    name="organization"
                    value={formData.organization}
                    onChange={handleChange}
                    className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                    placeholder="Department of Defense"
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-green-400 text-sm font-mono mb-2">SUBJECT *</label>
                    <input
                      type="text"
                      name="subject"
                      value={formData.subject}
                      onChange={handleChange}
                      className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                      placeholder="Security Inquiry"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-green-400 text-sm font-mono mb-2">URGENCY</label>
                    <select
                      name="urgency"
                      value={formData.urgency}
                      onChange={handleChange}
                      className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 focus:border-green-400 focus:outline-none transition-colors font-mono"
                    >
                      <option value="normal">Normal</option>
                      <option value="high">High Priority</option>
                      <option value="critical">Critical/Emergency</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="block text-green-400 text-sm font-mono mb-2">MESSAGE *</label>
                  <textarea
                    name="message"
                    value={formData.message}
                    onChange={handleChange}
                    rows={6}
                    className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono resize-none"
                    placeholder="Describe your security requirements or incident details..."
                    required
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono flex items-center justify-center space-x-2"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-black"></div>
                      <span>SENDING...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      <span>SEND SECURE MESSAGE</span>
                    </>
                  )}
                </button>
              </form>
            </div>

            {/* Contact Information */}
            <div className="space-y-6">
              {contactInfo.map((info, index) => (
                <div key={index} className="bg-black/70 border border-green-500/30 rounded-lg p-6 backdrop-blur-sm">
                  <div className="flex items-start space-x-4">
                    <info.icon className="w-6 h-6 text-green-400 mt-1" />
                    <div>
                      <h3 className="text-lg font-bold text-green-400 font-mono mb-2">{info.title}</h3>
                      <p className="text-green-300 font-mono mb-1">{info.details}</p>
                      <p className="text-green-200 text-sm">{info.description}</p>
                    </div>
                  </div>
                </div>
              ))}

              {/* Emergency Notice */}
              <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-6">
                <h3 className="text-lg font-bold text-red-400 font-mono mb-3">SECURITY EMERGENCY?</h3>
                <p className="text-red-300 text-sm mb-4">
                  If you're experiencing an active cyber attack or security breach, contact our emergency response team
                  immediately.
                </p>
                <button className="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-lg transition-colors font-mono">
                  EMERGENCY RESPONSE
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  )
}
