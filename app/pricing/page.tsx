"use client"

import { useState } from "react"
import { Navigation } from "@/components/navigation"
import { ParticleBackground } from "@/components/particle-background"
import { Footer } from "@/components/footer"
import { Check, Shield, Zap, Crown, Star } from "lucide-react"

export default function PricingPage() {
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">("monthly")

  const plans = [
    {
      name: "Basic Shield",
      icon: Shield,
      description: "Essential protection for small organizations",
      monthlyPrice: 99,
      annualPrice: 990,
      features: [
        "Basic DDoS Protection",
        "Standard Firewall",
        "24/7 Monitoring",
        "Email Support",
        "Up to 10GB bandwidth",
        "Basic threat detection",
        "SSL certificates",
        "Monthly reports",
      ],
      popular: false,
      color: "green",
    },
    {
      name: "Professional Guard",
      icon: Zap,
      description: "Advanced security for growing enterprises",
      monthlyPrice: 299,
      annualPrice: 2990,
      features: [
        "Advanced DDoS Protection",
        "AI-Powered Firewall",
        "Real-time Monitoring",
        "Priority Support",
        "Up to 100GB bandwidth",
        "Advanced threat intelligence",
        "Custom SSL certificates",
        "Weekly reports",
        "API access",
        "Custom rules",
        "Geo-blocking",
        "Rate limiting",
      ],
      popular: true,
      color: "blue",
    },
    {
      name: "Enterprise Fortress",
      icon: Crown,
      description: "Maximum security for critical infrastructure",
      monthlyPrice: 999,
      annualPrice: 9990,
      features: [
        "Military-grade DDoS Protection",
        "Neural Network Firewall",
        "Continuous Monitoring",
        "Dedicated Support Team",
        "Unlimited bandwidth",
        "Zero-day threat protection",
        "Enterprise SSL management",
        "Real-time reports",
        "Full API access",
        "Custom integrations",
        "Advanced analytics",
        "Compliance reporting",
        "Dedicated infrastructure",
        "SLA guarantees",
      ],
      popular: false,
      color: "purple",
    },
  ]

  const getPrice = (plan: (typeof plans)[0]) => {
    return billingCycle === "monthly" ? plan.monthlyPrice : plan.annualPrice
  }

  const getColorClasses = (color: string, popular: boolean) => {
    const baseClasses =
      "bg-black/70 border backdrop-blur-sm rounded-lg p-8 relative transition-all duration-300 hover:scale-105"

    if (popular) {
      return `${baseClasses} border-blue-500/50 shadow-lg shadow-blue-500/25`
    }

    switch (color) {
      case "green":
        return `${baseClasses} border-green-500/30 hover:border-green-400/50`
      case "blue":
        return `${baseClasses} border-blue-500/30 hover:border-blue-400/50`
      case "purple":
        return `${baseClasses} border-purple-500/30 hover:border-purple-400/50`
      default:
        return `${baseClasses} border-green-500/30`
    }
  }

  const getButtonClasses = (color: string, popular: boolean) => {
    if (popular) {
      return "w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 font-mono"
    }

    switch (color) {
      case "green":
        return "w-full bg-green-600 hover:bg-green-500 text-black font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 font-mono"
      case "purple":
        return "w-full bg-purple-600 hover:bg-purple-500 text-white font-bold py-3 px-6 rounded-lg transition-all duration-300 transform hover:scale-105 font-mono"
      default:
        return "w-full border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-3 px-6 rounded-lg transition-all duration-300 font-mono"
    }
  }

  return (
    <div className="min-h-screen bg-black text-green-400">
      <ParticleBackground />
      <Navigation />

      <div className="pt-20 pb-16">
        <div className="container mx-auto px-6">
          {/* Header */}
          <div className="text-center mb-16">
            <h1 className="text-4xl font-bold text-green-400 mb-4 font-mono">SECURITY PLANS</h1>
            <p className="text-green-200 text-lg max-w-3xl mx-auto mb-8">
              Choose the perfect security solution for your organization. All plans include our core protection features
              with varying levels of advanced capabilities.
            </p>

            {/* Billing Toggle */}
            <div className="flex items-center justify-center space-x-4 mb-8">
              <span className={`font-mono ${billingCycle === "monthly" ? "text-green-400" : "text-green-600"}`}>
                Monthly
              </span>
              <button
                onClick={() => setBillingCycle(billingCycle === "monthly" ? "annual" : "monthly")}
                className="relative inline-flex h-6 w-11 items-center rounded-full bg-gray-800 transition-colors focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-offset-2"
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-green-400 transition-transform ${
                    billingCycle === "annual" ? "translate-x-6" : "translate-x-1"
                  }`}
                />
              </button>
              <span className={`font-mono ${billingCycle === "annual" ? "text-green-400" : "text-green-600"}`}>
                Annual
              </span>
              {billingCycle === "annual" && (
                <span className="bg-green-600 text-black px-2 py-1 rounded text-xs font-bold">SAVE 17%</span>
              )}
            </div>
          </div>

          {/* Pricing Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-16">
            {plans.map((plan, index) => (
              <div key={index} className={getColorClasses(plan.color, plan.popular)}>
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                    <div className="bg-blue-600 text-white px-4 py-1 rounded-full text-sm font-bold flex items-center space-x-1">
                      <Star className="w-4 h-4" />
                      <span>MOST POPULAR</span>
                    </div>
                  </div>
                )}

                <div className="text-center mb-6">
                  <plan.icon
                    className={`w-12 h-12 mx-auto mb-4 ${
                      plan.popular
                        ? "text-blue-400"
                        : plan.color === "green"
                          ? "text-green-400"
                          : plan.color === "purple"
                            ? "text-purple-400"
                            : "text-green-400"
                    }`}
                  />
                  <h3
                    className={`text-2xl font-bold font-mono mb-2 ${
                      plan.popular
                        ? "text-blue-400"
                        : plan.color === "green"
                          ? "text-green-400"
                          : plan.color === "purple"
                            ? "text-purple-400"
                            : "text-green-400"
                    }`}
                  >
                    {plan.name}
                  </h3>
                  <p className="text-green-300 text-sm">{plan.description}</p>
                </div>

                <div className="text-center mb-6">
                  <div
                    className={`text-4xl font-bold font-mono mb-2 ${
                      plan.popular
                        ? "text-blue-400"
                        : plan.color === "green"
                          ? "text-green-400"
                          : plan.color === "purple"
                            ? "text-purple-400"
                            : "text-green-400"
                    }`}
                  >
                    ${getPrice(plan).toLocaleString()}
                  </div>
                  <div className="text-green-300 text-sm">per {billingCycle === "monthly" ? "month" : "year"}</div>
                </div>

                <div className="space-y-3 mb-8">
                  {plan.features.map((feature, featureIndex) => (
                    <div key={featureIndex} className="flex items-center space-x-3">
                      <Check className="w-4 h-4 text-green-400 flex-shrink-0" />
                      <span className="text-green-300 text-sm">{feature}</span>
                    </div>
                  ))}
                </div>

                <button className={getButtonClasses(plan.color, plan.popular)}>
                  {plan.popular ? "START PROTECTION" : "CHOOSE PLAN"}
                </button>
              </div>
            ))}
          </div>

          {/* Enterprise Contact */}
          <div className="bg-black/70 border border-green-500/30 rounded-lg p-8 backdrop-blur-sm text-center">
            <h3 className="text-2xl font-bold text-green-400 mb-4 font-mono">CUSTOM ENTERPRISE SOLUTIONS</h3>
            <p className="text-green-200 mb-6 max-w-2xl mx-auto">
              Need a tailored security solution for your specific requirements? Our enterprise team can create a custom
              protection plan designed for your unique infrastructure needs.
            </p>
            <div className="space-x-4">
              <button className="bg-green-600 hover:bg-green-500 text-black font-bold py-3 px-8 rounded-lg transition-all duration-300 transform hover:scale-105 font-mono">
                CONTACT SALES
              </button>
              <button className="border border-green-500 text-green-400 hover:bg-green-500/10 font-bold py-3 px-8 rounded-lg transition-all duration-300 font-mono">
                SCHEDULE DEMO
              </button>
            </div>
          </div>
        </div>
      </div>

      <Footer />
    </div>
  )
}
