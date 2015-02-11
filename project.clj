(defproject herd-node "0.1.0-SNAPSHOT"
  :description "anonymous quanta"
  :url "http://example.com/FIXME"
  :license {:name "BSD"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :plugins [[lein-cljsbuild "1.0.3"]
            [com.cemerick/piggieback "0.1.3"]]
  :dependencies [[org.clojure/clojure "1.6.0"]
                 ;[org.clojure/core.async "0.1.346.0-17112a-alpha"]
                 [org.clojure/core.async "0.1.338.0-5c5012-alpha"]
                 [org.clojure/clojurescript "0.0-2644"]
                 [org.bodil/cljs-noderepl "0.1.11"]]
  :repl-options {:nrepl-middleware [cemerick.piggieback/wrap-cljs-repl]}
  :cljsbuild {:builds [{:source-paths ["src"]
                        :compiler {:target :nodejs
                                   :hashbang "/usr/bin/env node\nrequire('source-map-support').install();"
                                   :output-to "target/herd.js"
                                   :source-map "target/herd.js.map"
                                   :cache-analysis true
                                   :optimizations :simple
                                   :static-fns true
                                   :pretty-print true}}]})
