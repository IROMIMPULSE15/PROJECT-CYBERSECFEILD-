"use client"

import { useEffect, useRef } from "react"

export function ParticleBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext("2d")
    if (!ctx) return

    canvas.width = window.innerWidth
    canvas.height = window.innerHeight

    const features = [
      "QUANTUM SECURE",
      "NEURAL DEFENSE",
      "ZERO TRUST",
      "BLOCKCHAIN",
      "AI SHIELD",
      "CRYPTOGRAPHY",
      "FIREWALL",
      "DEEP SCAN",
      "THREAT DETECT",
      "SECURE NODE",
      "CYBER GUARD",
      "DATA VAULT",
    ]

    interface Particle {
      x: number
      y: number
      vx: number
      vy: number
      size: number
      opacity: number
      targetX: number
      targetY: number
      text: string
      isText: boolean
      burstTimer: number
      reformTimer: number
      color: string
      textOpacity: number
      phase: "particle" | "forming" | "text" | "dissolving"
    }

    const particles: Particle[] = []

    // Create initial particles with better distribution
    for (let i = 0; i < 80; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        size: Math.random() * 1.5 + 0.5,
        opacity: Math.random() * 0.4 + 0.1,
        targetX: 0,
        targetY: 0,
        text: features[i % features.length],
        isText: false,
        burstTimer: Math.random() * 400 + 200, // Longer, more varied timing
        reformTimer: 0,
        color: `rgb(0, ${Math.floor(Math.random() * 100 + 155)}, 0)`,
        textOpacity: 0,
        phase: "particle",
      })
    }

    function drawText(ctx: CanvasRenderingContext2D, text: string, x: number, y: number, opacity: number) {
      ctx.font = "bold 14px monospace"
      ctx.fillStyle = `rgba(0, 255, 0, ${opacity})`
      ctx.strokeStyle = `rgba(0, 128, 0, ${opacity * 0.3})`
      ctx.textAlign = "center"
      ctx.lineWidth = 0.5
      ctx.strokeText(text, x, y)
      ctx.fillText(text, x, y)
    }

    function animate() {
      if (!ctx || !canvas) return

      // Smoother fade effect
      ctx.fillStyle = "rgba(0, 0, 0, 0.03)"
      ctx.fillRect(0, 0, canvas.width, canvas.height)

      particles.forEach((particle, index) => {
        // Phase management with smoother transitions
        switch (particle.phase) {
          case "particle":
            particle.burstTimer--
            if (particle.burstTimer <= 0) {
              particle.phase = "forming"
              particle.targetX = Math.random() * (canvas.width * 0.7) + canvas.width * 0.15
              particle.targetY = Math.random() * (canvas.height * 0.7) + canvas.height * 0.15
              particle.reformTimer = 120 // Longer formation time
            }
            break

          case "forming":
            particle.reformTimer--
            const formProgress = (120 - particle.reformTimer) / 120
            particle.textOpacity = Math.min(formProgress * 2, 1)

            if (particle.reformTimer <= 0) {
              particle.phase = "text"
              particle.reformTimer = 180 // Display text longer
              particle.textOpacity = 1
            }
            break

          case "text":
            particle.reformTimer--
            if (particle.reformTimer <= 0) {
              particle.phase = "dissolving"
              particle.reformTimer = 60
            }
            break

          case "dissolving":
            particle.reformTimer--
            const dissolveProgress = particle.reformTimer / 60
            particle.textOpacity = dissolveProgress

            if (particle.reformTimer <= 0) {
              particle.phase = "particle"
              particle.burstTimer = Math.random() * 600 + 300 // Longer wait before next burst
              particle.textOpacity = 0
            }
            break
        }

        if (particle.phase === "forming" || particle.phase === "text" || particle.phase === "dissolving") {
          // Smooth movement to target
          const moveSpeed = particle.phase === "forming" ? 0.08 : 0.02
          particle.x += (particle.targetX - particle.x) * moveSpeed
          particle.y += (particle.targetY - particle.y) * moveSpeed

          if (particle.textOpacity > 0) {
            drawText(ctx, particle.text, particle.x, particle.y, particle.textOpacity)
          }
        } else {
          // Normal particle movement
          particle.x += particle.vx
          particle.y += particle.vy

          // Wrap around screen
          if (particle.x < 0) particle.x = canvas.width
          if (particle.x > canvas.width) particle.x = 0
          if (particle.y < 0) particle.y = canvas.height
          if (particle.y > canvas.height) particle.y = 0

          // Draw particle
          ctx.beginPath()
          ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2)
          ctx.fillStyle = particle.color
          ctx.fill()

          // Draw connections with reduced frequency
          if (index % 2 === 0) {
            // Only every other particle draws connections
            particles.slice(index + 1, index + 5).forEach((otherParticle) => {
              if (otherParticle.phase === "particle") {
                const dx = particle.x - otherParticle.x
                const dy = particle.y - otherParticle.y
                const distance = Math.sqrt(dx * dx + dy * dy)

                if (distance < 80) {
                  ctx.beginPath()
                  ctx.moveTo(particle.x, particle.y)
                  ctx.lineTo(otherParticle.x, otherParticle.y)
                  ctx.strokeStyle = `rgba(0, 255, 0, ${0.05 * (1 - distance / 80)})`
                  ctx.lineWidth = 0.3
                  ctx.stroke()
                }
              }
            })
          }
        }
      })

      requestAnimationFrame(animate)
    }

    animate()

    const handleResize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }

    window.addEventListener("resize", handleResize)
    return () => window.removeEventListener("resize", handleResize)
  }, [])

  return (
    <canvas ref={canvasRef} className="fixed inset-0 pointer-events-none z-0" style={{ background: "transparent" }} />
  )
}
