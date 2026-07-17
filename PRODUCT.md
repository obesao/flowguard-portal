# Product

## Register

product

## Platform

web

## Users

Equipe técnica de NOC (network operations) de um provedor de internet, operando o portal principalmente em monitor dedicado/desktop durante a rotina, com checagem ocasional remota (celular) fora do NOC quando um alerta chega fora de horário. O contexto de uso mais crítico é sob pressão: um incidente de DDoS ou abuso de cliente ativo, onde a pessoa precisa escanear dado denso rapidamente e agir (mitigar) sem fricção.

## Product Purpose

Portal único de operação de rede que unifica dois sistemas de detecção que rodam como daemons independentes — FlowGuard (DDoS/anomalia de tráfego por prefixo protegido) e ClientGuard (cliente comprometido/abusivo: scan, spam, C2, exfiltração) — com visão de status, histórico de ataques/sinais e mitigação direta na borda (RTBH, FlowSpec, ACL via SSH). Sucesso é a equipe identificar e conter um incidente real sem sair do portal nem precisar cruzar dados de ferramentas separadas.

## Positioning

O único lugar que junta visibilidade (DDoS + abuso de cliente) e ação (mitigação direta na borda) num só fluxo, sem trocar de ferramenta no meio de um incidente.

## Brand Personality

Calmo, denso, confiável — precisão de dado tipo Grafana/Datadog, não persuasão tipo landing page de SaaS. A interface deve reduzir ruído visual exatamente no momento de maior estresse (incidente ativo), não competir por atenção com decoração.

## Anti-references

Nada de estética de marketing SaaS genérica: sem gradientes decorativos, sem cards fofos empilhados, sem tom de "produto vendendo plano". Isto é ferramenta operacional interna, não superfície de conversão.

## Design Principles

- Calma sob incidente: densidade de dado e hierarquia clara reduzem ruído justamente quando o operador está sob mais estresse, não o contrário.
- Nunca só cor: severidade e estado sempre carregam um segundo sinal (ícone, texto, posição) — a tela pode ser vista em print/WhatsApp ou por daltônico sem perder significado.
- Um relance, dois sistemas: FlowGuard e ClientGuard devem ser triáveis lado a lado sem forçar troca de aba pra entender "está tudo bem?".
- Confiança ganha por precisão, não por polish decorativo: todo número exibido precisa ser real e rastreável até a origem (flow_aggs, socket do daemon).

## Accessibility & Inclusion

Padrão WCAG AA: contraste mínimo 4.5:1 em texto normal, 3:1 em texto grande/UI. Severidade/estado nunca codificados só por cor.
