import React, { Component } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error:", error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    if (this.props.onReset) {
      this.props.onReset();
    }
  };

  render() {
    if (this.state.hasError) {
      return (
        <section className="py-16 px-4 max-w-4xl mx-auto my-8">
          <div className="p-8 rounded-3xl bg-red-950/90 border-2 border-red-500/50 text-white shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-12 h-12 rounded-2xl bg-red-500/20 border border-red-500/40 flex items-center justify-center text-red-400">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-xl font-black text-red-200">
                  {this.props.title || "Scanner Component Error"}
                </h3>
                <p className="text-xs text-red-300/80 font-mono mt-0.5">
                  An unexpected error occurred while loading this view.
                </p>
              </div>
            </div>

            <div className="bg-black/50 p-4 rounded-xl border border-red-900/60 font-mono text-xs text-red-200 mb-6 overflow-x-auto">
              {this.state.error?.message || "Component failed to render."}
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={this.handleReset}
                className="px-5 py-2.5 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center gap-2 transition-colors shadow-lg shadow-red-950/50"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Retry / Reset Scanner</span>
              </button>
            </div>
          </div>
        </section>
      );
    }

    return this.props.children;
  }
}
