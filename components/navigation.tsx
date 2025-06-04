"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Shield, Menu, X, User, LogOut } from "lucide-react"
import { useAuth } from "@/components/auth-provider"

export function Navigation() {
  const [isOpen, setIsOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const { user, logout } = useAuth()
  const router = useRouter()

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50)
    }
    window.addEventListener("scroll", handleScroll)
    return () => window.removeEventListener("scroll", handleScroll)
  }, [])

  const handleLogout = () => {
    logout()
    router.push("/")
  }

  return (
    <nav
      className={`fixed top-0 w-full z-50 transition-all duration-300 ${
        scrolled ? "bg-black/90 backdrop-blur-md border-b border-green-500/30" : "bg-transparent"
      }`}
    >
      <div className="container mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link href="/" className="flex items-center space-x-3 group">
            <Shield className="w-8 h-8 text-green-400 group-hover:animate-pulse" />
            <span className="text-xl font-bold text-green-400 font-mono">CYBERDEFENSE</span>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <Link href="/" className="text-green-300 hover:text-green-400 transition-colors font-mono">
              Home
            </Link>
            <Link href="/dashboard" className="text-green-300 hover:text-green-400 transition-colors font-mono">
              Dashboard
            </Link>
            <Link href="/pricing" className="text-green-300 hover:text-green-400 transition-colors font-mono">
              Pricing
            </Link>
            <Link href="/about" className="text-green-300 hover:text-green-400 transition-colors font-mono">
              About
            </Link>
            <Link href="/contact" className="text-green-300 hover:text-green-400 transition-colors font-mono">
              Contact
            </Link>
          </div>

          {/* Auth Buttons */}
          <div className="hidden md:flex items-center space-x-4">
            {user ? (
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2 text-green-400">
                  <User className="w-4 h-4" />
                  <span className="font-mono">{user.email}</span>
                </div>
                <button
                  onClick={handleLogout}
                  className="flex items-center space-x-2 text-green-300 hover:text-green-400 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  <span>Logout</span>
                </button>
              </div>
            ) : (
              <>
                <Link href="/login" className="text-green-400 hover:text-green-300 transition-colors font-mono">
                  Login
                </Link>
                <Link
                  href="/signup"
                  className="bg-green-600 hover:bg-green-500 text-black px-4 py-2 rounded-lg transition-colors font-mono font-bold"
                >
                  Sign Up
                </Link>
              </>
            )}
          </div>

          {/* Mobile Menu Button */}
          <button onClick={() => setIsOpen(!isOpen)} className="md:hidden text-green-400 hover:text-green-300">
            {isOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>

        {/* Mobile Menu */}
        {isOpen && (
          <div className="md:hidden bg-black/95 backdrop-blur-md border-t border-green-500/30">
            <div className="px-2 pt-2 pb-3 space-y-1">
              <Link
                href="/"
                className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                onClick={() => setIsOpen(false)}
              >
                Home
              </Link>
              <Link
                href="/dashboard"
                className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                onClick={() => setIsOpen(false)}
              >
                Dashboard
              </Link>
              <Link
                href="/pricing"
                className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                onClick={() => setIsOpen(false)}
              >
                Pricing
              </Link>
              <Link
                href="/about"
                className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                onClick={() => setIsOpen(false)}
              >
                About
              </Link>
              <Link
                href="/contact"
                className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                onClick={() => setIsOpen(false)}
              >
                Contact
              </Link>
              {user ? (
                <button
                  onClick={() => {
                    handleLogout()
                    setIsOpen(false)
                  }}
                  className="block w-full text-left px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                >
                  Logout
                </button>
              ) : (
                <>
                  <Link
                    href="/login"
                    className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                    onClick={() => setIsOpen(false)}
                  >
                    Login
                  </Link>
                  <Link
                    href="/signup"
                    className="block px-3 py-2 text-green-300 hover:text-green-400 transition-colors font-mono"
                    onClick={() => setIsOpen(false)}
                  >
                    Sign Up
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </nav>
  )
}
