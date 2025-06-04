"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Shield, Eye, EyeOff, Lock, Mail, User } from "lucide-react"
import { useAuth } from "@/components/auth-provider"
import { ParticleBackground } from "@/components/particle-background"
import { useToast } from "@/hooks/use-toast"

export default function SignupPage() {
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
  })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const { signup } = useAuth()
  const router = useRouter()
  const { toast } = useToast()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (formData.password !== formData.confirmPassword) {
      toast({
        title: "Password Mismatch",
        description: "Passwords do not match. Please try again.",
        variant: "destructive",
      })
      return
    }

    setLoading(true)

    try {
      const success = await signup(formData.email, formData.password, formData.name)
      if (success) {
        toast({
          title: "Registration Successful",
          description: "Welcome to CyberDefense Platform",
        })
        router.push("/dashboard")
      } else {
        toast({
          title: "Registration Failed",
          description: "Unable to create account. Please try again.",
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

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }))
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
            <h1 className="text-2xl font-bold text-green-400 font-mono mb-2">REQUEST ACCESS</h1>
            <p className="text-green-300 text-sm">Create your secure account</p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div>
              <label className="block text-green-400 text-sm font-mono mb-2">
                <User className="w-4 h-4 inline mr-2" />
                FULL NAME
              </label>
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
              <label className="block text-green-400 text-sm font-mono mb-2">
                <Mail className="w-4 h-4 inline mr-2" />
                EMAIL ADDRESS
              </label>
              <input
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                placeholder="user@organization.gov"
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
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
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

            <div>
              <label className="block text-green-400 text-sm font-mono mb-2">
                <Lock className="w-4 h-4 inline mr-2" />
                CONFIRM PASSWORD
              </label>
              <input
                type="password"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                className="w-full bg-gray-900/50 border border-green-500/30 rounded-lg px-4 py-3 text-green-400 placeholder-green-600 focus:border-green-400 focus:outline-none transition-colors font-mono"
                placeholder="••••••••••••"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-500 disabled:bg-green-800 text-black font-bold py-3 px-4 rounded-lg transition-all duration-300 transform hover:scale-105 disabled:scale-100 font-mono"
            >
              {loading ? "PROCESSING..." : "REQUEST ACCESS"}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-6 text-center">
            <p className="text-green-300 text-sm">
              Already have access?{" "}
              <Link href="/login" className="text-green-400 hover:text-green-300 font-mono">
                Sign In
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
