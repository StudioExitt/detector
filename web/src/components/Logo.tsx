import { useId } from 'react'

// public/favicon.svg 와 동일한 디자인
export default function Logo({ className }: { className?: string }) {
  // 사이드바가 동시에 여러 개 렌더링될 수 있어 gradient id 를 고유하게 생성
  const gid = useId()
  return (
    <svg viewBox="0 0 64 64" className={className} aria-hidden="true">
      <defs>
        <linearGradient id={gid} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3b82f6" />
          <stop offset="1" stopColor="#4338ca" />
        </linearGradient>
      </defs>
      <path d="M32 3 8 12v18c0 15.5 10.3 26.6 24 31 13.7-4.4 24-15.5 24-31V12L32 3Z" fill={`url(#${gid})`} />
      <circle cx="32" cy="31" r="15" fill="none" stroke="#fff" strokeOpacity=".35" strokeWidth="2" />
      <circle cx="32" cy="31" r="8" fill="none" stroke="#fff" strokeOpacity=".55" strokeWidth="2" />
      <path d="M32 31 43 20" stroke="#fff" strokeWidth="3" strokeLinecap="round" />
      <circle cx="32" cy="31" r="3" fill="#fff" />
      <circle cx="40.5" cy="37.5" r="3.5" fill="#f43f5e" stroke="#fff" strokeWidth="1.5" />
    </svg>
  )
}
