"use client"

import Link from "next/link"
import { Shield, Mail, Phone, MapPin } from "lucide-react"

export function Footer() {
  return (
    <footer className="relative py-16 z-10 border-t border-green-500/30">
      <div className="container mx-auto px-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center mb-6">
              <Shield className="w-8 h-8 text-green-400 mr-3" />
              <div className="text-2xl font-bold text-green-400 font-mono">CYBERDEFENSE</div>
            </div>
            <p className="text-green-200 mb-6 max-w-md">
              Advanced AI-powered security platform protecting critical national infrastructure from sophisticated cyber
              threats and coordinated attacks.
            </p>
            <div className="space-y-3">
              <div className="flex items-center text-green-300">
                <Mail className="w-4 h-4 mr-3" />
                <span>security@cyberdefense.gov</span>
              </div>
              <div className="flex items-center text-green-300">
                <Phone className="w-4 h-4 mr-3" />
                <span>+1 (555) CYBER-SEC</span>
              </div>
              <div className="flex items-center text-green-300">
                <MapPin className="w-4 h-4 mr-3" />
                <span>Secure Operations Center, Washington DC</span>
              </div>
            </div>
          </div>

          {/* Solutions */}
          <div>
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">SOLUTIONS</h4>
            <div className="space-y-2">
              {[
                "DDoS Protection",
                "Threat Detection",
                "Zero Trust Security",
                "API Protection",
                "Data Encryption",
                "Incident Response",
              ].map((item, index) => (
                <div key={index} className="text-green-300 hover:text-green-400 cursor-pointer transition-colors">
                  {item}
                </div>
              ))}
            </div>
          </div>

          {/* Resources */}
          <div>
            <h4 className="text-lg font-bold text-green-400 mb-4 font-mono">RESOURCES</h4>
            <div className="space-y-2">
              {[
                { label: "Dashboard", href: "/dashboard" },
                { label: "Pricing", href: "/pricing" },
                { label: "About", href: "/about" },
                { label: "Contact", href: "/contact" },
                { label: "Support Portal", href: "#" },
                { label: "Documentation", href: "#" },
              ].map((item, index) => (
                <Link
                  key={index}
                  href={item.href}
                  className="block text-green-300 hover:text-green-400 cursor-pointer transition-colors"
                >
                  {item.label}
                </Link>
              ))}
            </div>
          </div>
        </div>

        <div className="border-t border-green-500/30 mt-12 pt-8">
          <div className="flex flex-col md:flex-row justify-between items-center">
            <div className="text-green-300 text-sm mb-4 md:mb-0">
              © 2024 CyberDefense Platform. Classified Security System.
            </div>
            <div className="flex space-x-6 text-sm text-green-300">
              <span className="hover:text-green-400 cursor-pointer">Privacy Policy</span>
              <span className="hover:text-green-400 cursor-pointer">Terms of Service</span>
              <span className="hover:text-green-400 cursor-pointer">Security Disclosure</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}
