(ns herd-node.misc ;; we might make this tools.cljs or something.
  (:require [cljs.core :as cljs]
            [cljs.nodejs :as node]))


(defn is? [role roles]
  "Tests if a role is part of the given roles, return it."
  (first (filter #(= role %) roles)))
