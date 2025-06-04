"use client"

import { createContext, useContext, useState, useEffect, type ReactNode } from "react"

interface User {
  id: string
  email: string
  name: string
  plan: string
}

interface AuthContextType {
  user: User | null
  login: (email: string, password: string) => Promise<boolean>
  signup: (email: string, password: string, name: string) => Promise<boolean>
  logout: () => void
  loading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Check for stored user session
    const storedUser = localStorage.getItem("cyberdefense_user")
    if (storedUser) {
      setUser(JSON.parse(storedUser))
    }
    setLoading(false)
  }, [])

  const login = async (email: string, password: string): Promise<boolean> => {
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1000))

    // Mock authentication
    if (email && password) {
      const mockUser: User = {
        id: "1",
        email,
        name: email.split("@")[0],
        plan: "Professional",
      }
      setUser(mockUser)
      localStorage.setItem("cyberdefense_user", JSON.stringify(mockUser))
      return true
    }
    return false
  }

  const signup = async (email: string, password: string, name: string): Promise<boolean> => {
    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 1000))

    // Mock registration
    if (email && password && name) {
      const mockUser: User = {
        id: "1",
        email,
        name,
        plan: "Basic",
      }
      setUser(mockUser)
      localStorage.setItem("cyberdefense_user", JSON.stringify(mockUser))
      return true
    }
    return false
  }

  const logout = () => {
    setUser(null)
    localStorage.removeItem("cyberdefense_user")
  }

  return <AuthContext.Provider value={{ user, login, signup, logout, loading }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
