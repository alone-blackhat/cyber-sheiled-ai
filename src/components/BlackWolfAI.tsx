import React, { useState, useEffect, useRef } from "react";
import Markdown from "react-markdown";
import { 
  ShieldAlert, Bot, User, Send, Trash2, HelpCircle, 
  ChevronRight, RefreshCw, Sparkles, Terminal, Copy, Check,
  Search, Code, HelpCircle as HelpIcon, Flame, Globe, Lock
} from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  timestamp: string;
}

interface ChatSession {
  id: string;
  title: string;
  messages: Message[];
  pinned?: boolean;
}

const markdownComponents = {
  h1: ({ children, ...props }: any) => <h1 className="text-sm font-bold text-emerald-400 font-mono mt-3 mb-1.5 border-b border-emerald-500/10 pb-1" {...props}>{children}</h1>,
  h2: ({ children, ...props }: any) => <h2 className="text-xs font-bold text-emerald-400 font-mono mt-2 mb-1" {...props}>{children}</h2>,
  h3: ({ children, ...props }: any) => <h3 className="text-xs font-semibold text-slate-300 font-mono mt-1.5 mb-1" {...props}>{children}</h3>,
  p: ({ children, ...props }: any) => <p className="mb-1.5 last:mb-0 leading-relaxed text-xs text-slate-300" {...props}>{children}</p>,
  ul: ({ children, ...props }: any) => <ul className="list-disc pl-4 mb-2 space-y-1 text-xs text-slate-300" {...props}>{children}</ul>,
  ol: ({ children, ...props }: any) => <ol className="list-decimal pl-4 mb-2 space-y-1 text-xs text-slate-300" {...props}>{children}</ol>,
  li: ({ children, ...props }: any) => <li className="text-slate-300 font-mono text-xs list-outside" {...props}>{children}</li>,
  blockquote: ({ children, ...props }: any) => <blockquote className="border-l-2 border-emerald-500/40 bg-emerald-500/5 px-3 py-1.5 rounded-r my-2 text-xs text-slate-300 italic font-mono" {...props}>{children}</blockquote>,
  code: ({ className, children, ...props }: any) => {
    const match = /language-(\w+)/.exec(className || "");
    const isInline = !match && typeof children === "string" && !children.includes("\n");
    return !isInline ? (
      <div className="my-2 border border-slate-800 bg-slate-950/80 rounded-lg overflow-hidden font-mono text-xs">
        <div className="bg-slate-900/90 px-3 py-1 border-b border-slate-800 flex justify-between items-center text-[10px] text-slate-500 uppercase tracking-widest font-bold">
          <span>{match ? match[1] : "code"}</span>
        </div>
        <pre className="p-3 overflow-x-auto text-emerald-300 leading-normal">
          <code className={className} {...props}>
            {children}
          </code>
        </pre>
      </div>
    ) : (
      <code className="bg-slate-900/80 text-emerald-300 border border-slate-800 px-1 py-0.5 rounded font-mono text-xs" {...props}>
        {children}
      </code>
    );
  }
};

export default function BlackWolfAI() {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>("");
  const [inputText, setInputText] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [streamingText, setStreamingText] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Suggested preloaded topics
  const initialSuggestions = [
    { text: "What is Deep Web?", icon: <Globe className="w-4 h-4 text-emerald-400" /> },
    { text: "Explain zero-day vulnerability", icon: <ShieldAlert className="w-4 h-4 text-cyan-400" /> },
    { text: "How to prevent phishing attacks?", icon: <Lock className="w-4 h-4 text-purple-400" /> },
    { text: "Give best practices for passwords", icon: <Terminal className="w-4 h-4 text-pink-400" /> }
  ];

  // Initialize chats from localStorage or load default
  useEffect(() => {
    const cached = localStorage.getItem("react_black_wolf_chats");
    if (cached) {
      try {
        const parsed = JSON.parse(cached);
        if (parsed && parsed.length > 0) {
          setSessions(parsed);
          setActiveSessionId(parsed[0].id);
          return;
        }
      } catch (e) {
        console.error("Failed to parse cached chats", e);
      }
    }

    // Default chat session
    const defaultId = `chat_${Date.now()}`;
    const defaultSession: ChatSession = {
      id: defaultId,
      title: "Threat Session 1",
      messages: [
        {
          role: "assistant",
          content: "Hi! I am **BLACK_WOLF AI**, your friendly cyber security assistant.\n\nHow can I help you stay safe and secure today? Ask me any security question, or paste an indicator (IP, URL, email) to start scanning.",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        }
      ]
    };
    setSessions([defaultSession]);
    setActiveSessionId(defaultId);
  }, []);

  // Save chats to localStorage whenever they change
  useEffect(() => {
    if (sessions.length > 0) {
      localStorage.setItem("react_black_wolf_chats", JSON.stringify(sessions));
    }
  }, [sessions]);

  // Scroll to bottom of chat
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [sessions, activeSessionId, streamingText, isStreaming]);

  // Expose global callback for vanilla JS dashboard integrations
  useEffect(() => {
    (window as any).sendSuggestedCopilotQuery = (query: string) => {
      if (typeof (window as any).navigateToTab === "function") {
        (window as any).navigateToTab("cyber-emergency");
      }
      setInputText(query);
      if (query && query !== "Ask any custom security query...") {
        handleSendMessage(query);
      }
    };
    return () => {
      delete (window as any).sendSuggestedCopilotQuery;
    };
  }, [activeSessionId, sessions, inputText]);

  const activeSession = sessions.find(s => s.id === activeSessionId);

  const createNewSession = () => {
    const newId = `chat_${Date.now()}`;
    const newSession: ChatSession = {
      id: newId,
      title: `Threat Session ${sessions.length + 1}`,
      messages: [
        {
          role: "assistant",
          content: "Hi! I am **BLACK_WOLF AI**, your friendly and professional Cyber Security Assistant.\n\nLet me know what you would like to analyze or learn today!",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        }
      ]
    };
    setSessions(prev => [newSession, ...prev]);
    setActiveSessionId(newId);
  };

  const deleteSession = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (sessions.length <= 1) {
      // Just clear the messages of the only session
      setSessions(prev => prev.map(s => s.id === id ? {
        ...s,
        messages: [{
          role: "assistant",
          content: "System log reset completed. How can I help you?",
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
        }]
      } : s));
      return;
    }

    const filtered = sessions.filter(s => s.id !== id);
    setSessions(filtered);
    if (activeSessionId === id) {
      setActiveSessionId(filtered[0].id);
    }
  };

  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputText).trim();
    if (!text) return;

    if (!textToSend) {
      setInputText("");
    }

    // Add user message
    const userMsg: Message = {
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    };

    let updatedSessionTitle = activeSession?.title || "Threat Session";
    if (activeSession && activeSession.title.startsWith("Threat Session") && activeSession.messages.length <= 2) {
      updatedSessionTitle = text.length > 25 ? text.substring(0, 22) + "..." : text;
    }

    setSessions(prev => prev.map(s => s.id === activeSessionId ? {
      ...s,
      title: updatedSessionTitle,
      messages: [...s.messages, userMsg]
    } : s));

    setIsAnalyzing(true);

    try {
      // Send request to server's analyze endpoint
      const response = await fetch("/api/analyze-threat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: text,
          activeCategoryId: null,
          topicTitle: null
        })
      });

      if (!response.ok) {
        throw new Error("Failed to receive response from backend");
      }

      const data = await response.json();
      const assistantReplyText = data.report || "I could not analyze this parameters right now.";

      // Simulate live streaming response
      setIsStreaming(true);
      setStreamingText("");
      let currentIdx = 0;
      const speed = assistantReplyText.length > 500 ? 5 : 12; // speed up for long reports
      
      const interval = setInterval(() => {
        if (currentIdx < assistantReplyText.length) {
          // Stream block of characters to make it smooth
          const chunkSize = assistantReplyText.length > 500 ? 5 : 2;
          const nextChunk = assistantReplyText.substring(currentIdx, currentIdx + chunkSize);
          setStreamingText(prev => prev + nextChunk);
          currentIdx += chunkSize;
        } else {
          clearInterval(interval);
          setIsStreaming(false);
          setStreamingText("");
          
          // Actually commit response to active session
          const assistantMsg: Message = {
            role: "assistant",
            content: assistantReplyText,
            timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
          };

          setSessions(prev => prev.map(s => s.id === activeSessionId ? {
            ...s,
            messages: [...s.messages, assistantMsg]
          } : s));
        }
      }, speed);

    } catch (err) {
      console.error(err);
      const assistantMsg: Message = {
        role: "assistant",
        content: "I am having trouble communicating with the secure central scanning core. Please check your network connection or try again later.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
      };
      setSessions(prev => prev.map(s => s.id === activeSessionId ? {
        ...s,
        messages: [...s.messages, assistantMsg]
      } : s));
    } finally {
      setIsAnalyzing(false);
    }
  };

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const filteredSessions = sessions.filter(s => 
    s.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    s.messages.some(m => m.content.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="flex h-full w-full rounded-xl overflow-hidden border border-slate-800 bg-slate-950/60 backdrop-blur-xl text-slate-100">
      
      {/* Sessions Left Sidebar */}
      <aside className="w-72 flex flex-col border-r border-slate-800 bg-slate-950/80 shrink-0">
        <div className="p-4 border-b border-slate-800">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldAlert className="w-5 h-5 filter drop-shadow-[0_0_6px_rgba(16,185,129,0.5)]" />
            </div>
            <div>
              <h2 className="text-sm font-semibold tracking-wider text-emerald-400 font-mono">BLACK_WOLF AI</h2>
              <p className="text-[10px] text-slate-500 font-mono">INTELLIGENCE COPILOT</p>
            </div>
          </div>

          <button 
            onClick={createNewSession}
            className="w-full flex items-center justify-center gap-2 py-2 px-4 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/20 hover:border-emerald-500/40 text-emerald-400 text-xs font-semibold font-mono transition-all duration-300 shadow-[0_0_10px_rgba(16,185,129,0.05)]"
          >
            <Sparkles className="w-3.5 h-3.5 animate-pulse" />
            NEW SECURITY SESSION
          </button>
        </div>

        {/* Search */}
        <div className="p-3 border-b border-slate-800/60">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-500" />
            <input 
              type="text" 
              placeholder="Search threat cache..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900/60 text-xs rounded-lg pl-9 pr-4 py-2 border border-slate-800 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all font-mono"
            />
          </div>
        </div>

        {/* Session List */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {filteredSessions.map((session) => {
            const isActive = session.id === activeSessionId;
            return (
              <div
                key={session.id}
                onClick={() => setActiveSessionId(session.id)}
                className={`group flex items-center justify-between p-3 rounded-lg cursor-pointer transition-all ${
                  isActive 
                    ? "bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.05)]" 
                    : "hover:bg-slate-900/40 border border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <div className="flex items-center gap-2.5 overflow-hidden">
                  <Terminal className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-emerald-400" : "text-slate-500 group-hover:text-slate-400"}`} />
                  <span className="text-xs truncate font-mono">{session.title}</span>
                </div>
                <button
                  onClick={(e) => deleteSession(session.id, e)}
                  className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-800 text-slate-500 hover:text-red-400 transition-all shrink-0"
                  title="Purge session"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            );
          })}
        </div>

        <div className="p-3 border-t border-slate-800 bg-slate-950/40 text-center">
          <p className="text-[10px] text-slate-600 font-mono">
            BLACK_WOLF &bull; Secure Protocol
          </p>
        </div>
      </aside>

      {/* Chat workspace area */}
      <main className="flex-1 flex flex-col bg-slate-950/20">
        
        {/* Header bar */}
        <header className="h-14 flex items-center justify-between px-6 border-b border-slate-800 bg-slate-950/40">
          <div className="flex items-center gap-3">
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <div className="text-left">
              <h3 className="text-xs font-semibold font-mono text-emerald-400 tracking-wider">
                {activeSession ? activeSession.title : "SECURE SHELL CHANNEL"}
              </h3>
              <p className="text-[9px] text-slate-500 font-mono uppercase">
                AES-256 GCM INTEGRATED ENVIRONMENT
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button 
              onClick={() => {
                if (activeSession) {
                  setSessions(prev => prev.map(s => s.id === activeSessionId ? {
                    ...s,
                    messages: [{
                      role: "assistant",
                      content: "Chat logs purged. Secure node active.",
                      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
                    }]
                  } : s));
                }
              }}
              className="p-1.5 rounded-lg border border-slate-800 bg-slate-900/50 text-slate-400 hover:text-emerald-400 hover:border-emerald-500/20 transition-all"
              title="Reset current logs"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </header>

        {/* Message feed */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeSession?.messages.map((msg, index) => {
            const isUser = msg.role === "user";
            return (
              <div 
                key={index} 
                className={`flex gap-4 ${isUser ? "justify-end" : "justify-start"}`}
              >
                {!isUser && (
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div className={`max-w-[85%] rounded-xl px-4 py-3 border text-sm flex flex-col space-y-1.5 ${
                  isUser 
                    ? "bg-slate-900/60 border-slate-800 text-slate-100" 
                    : "bg-slate-900/25 border-slate-800 text-slate-300"
                }`}>
                  <div className="flex items-center justify-between gap-8 border-b border-slate-800/40 pb-1.5 text-[10px] text-slate-500 font-mono">
                    <span>{isUser ? "CLIENT_USER // INGRESS" : "BLACK_WOLF // COGNITIVE_CORE"}</span>
                    <div className="flex items-center gap-2">
                      <span>{msg.timestamp}</span>
                      <button 
                        onClick={() => copyToClipboard(msg.content, index)}
                        className="p-0.5 hover:bg-slate-800 rounded transition-colors text-slate-500 hover:text-slate-300"
                        title="Copy message"
                      >
                        {copiedIndex === index ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>

                  <div className="markdown-body text-xs text-slate-300 leading-relaxed">
                    <Markdown components={markdownComponents}>{msg.content}</Markdown>
                  </div>
                </div>

                {isUser && (
                  <div className="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 flex items-center justify-center shrink-0">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            );
          })}

          {/* Streaming Response Indicator */}
          {isStreaming && (
            <div className="flex gap-4 justify-start">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4" />
              </div>
              <div className="max-w-[85%] rounded-xl px-4 py-3 border text-sm bg-slate-900/25 border-slate-800 text-slate-300 flex flex-col space-y-1.5">
                <div className="flex items-center justify-between gap-8 border-b border-slate-800/40 pb-1.5 text-[10px] text-slate-500 font-mono">
                  <span>BLACK_WOLF // STREAMING...</span>
                  <span>LIVE</span>
                </div>
                <div className="markdown-body text-xs text-slate-300 leading-relaxed">
                  <Markdown components={markdownComponents}>{streamingText}</Markdown>
                  <span className="inline-block w-1.5 h-3.5 ml-1 bg-emerald-400 animate-pulse"></span>
                </div>
              </div>
            </div>
          )}

          {/* Analyzing Loading State */}
          {isAnalyzing && !isStreaming && (
            <div className="flex gap-4 justify-start">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0">
                <RefreshCw className="w-4 h-4 animate-spin" />
              </div>
              <div className="max-w-[85%] rounded-xl px-4 py-3 border border-slate-800 bg-slate-900/10 text-slate-400 text-xs font-mono flex items-center gap-2">
                <span>BLACK_WOLF core intelligence processing query parameters...</span>
              </div>
            </div>
          )}

          {/* Suggested Prompts Block on empty chat or new chat */}
          {activeSession && activeSession.messages.length <= 1 && !isAnalyzing && !isStreaming && (
            <div className="pt-4 max-w-2xl mx-auto space-y-4">
              <div className="text-center space-y-1">
                <h4 className="text-xs font-semibold text-slate-400 font-mono uppercase tracking-wider">Suggested Exploration Topics</h4>
                <p className="text-[11px] text-slate-500">Select an prompt below to query the BLACK_WOLF intelligence database</p>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {initialSuggestions.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSendMessage(s.text)}
                    className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/20 hover:bg-slate-900/60 hover:border-emerald-500/30 text-left text-xs transition-all duration-300 group"
                  >
                    <div className="p-1.5 rounded bg-slate-950 group-hover:bg-emerald-500/10 transition-colors">
                      {s.icon}
                    </div>
                    <span className="text-slate-300 group-hover:text-emerald-400 font-mono transition-colors">{s.text}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Action input bar */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40">
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2 bg-slate-900/60 rounded-xl border border-slate-800 px-3 py-1.5 focus-within:border-emerald-500/50 focus-within:ring-1 focus-within:ring-emerald-500/20 transition-all max-w-4xl mx-auto"
          >
            <input 
              type="text" 
              placeholder="Query cyber threat intelligence, programming, networking, or science topics..." 
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              disabled={isAnalyzing || isStreaming}
              className="flex-1 bg-transparent text-sm focus:outline-none text-slate-200 py-1.5 px-1 placeholder-slate-500 font-mono"
            />
            <button
              type="submit"
              disabled={!inputText.trim() || isAnalyzing || isStreaming}
              className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 disabled:opacity-40 disabled:hover:bg-transparent disabled:border-transparent transition-all shrink-0"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
          <div className="text-center mt-2">
            <span className="text-[9px] text-slate-500 font-mono">
              BLACK_WOLF is geared for safe, non-malicious educational purposes. Do not submit actual secrets.
            </span>
          </div>
        </div>

      </main>

    </div>
  );
}
