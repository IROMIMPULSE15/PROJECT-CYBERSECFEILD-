"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Shield, Eye, EyeOff, Lock, Mail } from "lucide-react"
import { useAuth } from "@/components/auth-provider"
import { ParticleBackground } from "@/components/particle-background"
import { useToast } from "@/hooks/use-toast"

export default function LoginPage() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const router = useRouter()
  const { toast } = useToast()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)

    try {
      const success = await login(email, password)
      if (success) {
        toast({
          title: "Login Successful",
          description: "Welcome to CyberDefense Platform",
        })
        router.push("/dashboard")
      } else {
        toast({
          title: "Login Failed",
          description: "Invalid credentials. Please try again.",
          variant: "destructive",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "An error occurred. Please try again.",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-black text-green-400 flex items-center justify-center relative">
      <ParticleBackground />

      <div className="w-full max-w-md z-10">
        <div className="bg-black/80 backdrop-blur-md border border-green-500/30 rounded-lg p-8 shadow-2xl">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="flex items-center justify-center mb-4">
              <Shield className="w-12 h-12 text-green-400 animate-pulse" />
            </div>
            <h1 className="text-2xl font-bold text-green-400 font-mono mb-2">SECURE ACCESS</h1>
            <p className="text-green-300 text-sm">Enter your credentials to access the platform</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-green-400 text-sm font-mono mb-2">
                <Mail className="w-4 h-4 inline mr-2" />
                EMAIL ADDRESS
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                placeholder="user@cyberdefense.gov"
                required
              />
            </div>

            <div>
              <label className="block text-green-400 text-sm font-mono mb-2">
                <Lock className="w-4 h-4 inline mr-2" />
                PASSWORD
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 pr-12 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                  placeholder="••••••••••••"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-green-500 hover:text-green-400"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-4 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono"
            >
              {loading ? "AUTHENTICATING..." : "ACCESS GRANTED"}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-6 text-center">
            <p className="text-green-300 text-sm">
              Don't have access?{" "}
              <Link href="/signup" className="text-green-400 hover:text-green-300 font-mono">
                Request Authorization
              </Link>
            </p>
          </div>

          {/* Demo Credentials */}
          <div className="mt-6 p-4 bg-green-900/20 border border-green-500/30 rounded-lg">
            <p className="text-green-400 text-xs font-mono mb-2">DEMO CREDENTIALS:</p>
            <p className="text-green-300 text-xs font-mono">Email: demo@cyberdefense.gov</p>
            <p className="text-green-300 text-xs font-mono">Password: any password</p>
          </div>
        </div>
      </div>
    </div>
  )
}
